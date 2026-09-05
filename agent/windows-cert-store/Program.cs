// certen-cert-agent — signs 32 bytes with a key in the Windows certificate store.
//
// WHY THIS EXISTS AS A SEPARATE PROGRAM. Node cannot reach a Windows CNG key. A certificate issued by
// a corporate CA (Microsoft ADCS) or held on a PIV/CAC smartcard is non-exportable by design: the
// private key never leaves the key-storage provider, and there is no Node API that can ask a KSP or a
// card minidriver to sign. WebCrypto has no PKCS#11, and the OS certificate store is reachable from a
// browser for TLS client authentication only — which authenticates a session and cannot sign an
// arbitrary hash. So the signing has to happen in a process that can call CNG, and the signer talks to
// it over stdout. This is Runbook F §F6's "local signing agent", and it is the same shape whether the
// key is software-backed, TPM-backed, or on a card.
//
// THE ONE THING TO GET RIGHT. Accumulate's signing preimage — sha256(sigMdHash || txnHash) — is
// ALREADY a digest. Every call below is SignHash, never SignData. SignData would hash the digest a
// second time and emit a structurally perfect signature the network refuses, with nothing in the
// crypto or in any log to point at the cause.
//
//   certen-cert-agent --thumbprint <hex> --public-key
//       prints the PKIX/SPKI DER public key as hex. sha256 of these bytes is the key page entry.
//
//   certen-cert-agent --thumbprint <hex> --sign <64-hex-char preimage>
//       prints the signature as hex. ASN.1 DER for ECDSA; PKCS#1 v1.5 for RSA.
//
//   certen-cert-agent --thumbprint <hex> --describe
//       prints "<algorithm> <signatureType>" so a caller can discover the key type.
//
// Exit code 0 on success; 1 with a message on stderr otherwise. Nothing secret is ever printed.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}

string? thumbprint = null;
string? mode = null;
string? preimageHex = null;
var location = StoreLocation.CurrentUser;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--thumbprint": thumbprint = i + 1 < args.Length ? args[++i] : null; break;
        case "--public-key": mode = "public-key"; break;
        case "--describe": mode = "describe"; break;
        case "--sign": mode = "sign"; preimageHex = i + 1 < args.Length ? args[++i] : null; break;
        case "--machine": location = StoreLocation.LocalMachine; break;
        default: return Fail($"unknown argument: {args[i]}");
    }
}

if (string.IsNullOrWhiteSpace(thumbprint)) return Fail("--thumbprint is required");
if (mode is null) return Fail("one of --public-key, --describe or --sign is required");

// Thumbprints are often pasted from certmgr with spaces, and sometimes with a leading invisible
// left-to-right mark. Normalise rather than fail on something the user cannot see.
thumbprint = new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

using var store = new X509Store(StoreName.My, location);
store.Open(OpenFlags.ReadOnly);
var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
if (found.Count == 0)
    return Fail($"no certificate with thumbprint {thumbprint} in {location}\\My");

var cert = found[0];

using var ecdsa = cert.GetECDsaPrivateKey();
using var rsa = ecdsa is null ? cert.GetRSAPrivateKey() : null;
if (ecdsa is null && rsa is null)
    return Fail($"certificate {thumbprint} has no usable ECDSA or RSA private key");

// The wire signature type. Anything that is not P-256 would hash and sign fine here and then be
// refused by the network, so refuse it here instead, where the message can say why.
string signatureType;
if (ecdsa is not null)
{
    var curve = ecdsa.ExportParameters(false).Curve;
    if (!curve.Oid.Value!.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        return Fail($"unsupported EC curve {curve.Oid.FriendlyName ?? curve.Oid.Value}; Accumulate's ecdsaSha256 is P-256");
    signatureType = "ecdsaSha256";
}
else
{
    signatureType = "rsaSha256";
}

try
{
    switch (mode)
    {
        case "describe":
            Console.WriteLine($"{(ecdsa is not null ? "ECDSA-P256" : $"RSA-{rsa!.KeySize}")} {signatureType}");
            return 0;

        case "public-key":
        {
            // PKIX/SPKI DER — what the network parses, and what it hashes to find the key on the page.
            var spki = ecdsa is not null ? ecdsa.ExportSubjectPublicKeyInfo() : rsa!.ExportSubjectPublicKeyInfo();
            Console.WriteLine(Convert.ToHexString(spki).ToLowerInvariant());
            return 0;
        }

        case "sign":
        {
            if (string.IsNullOrWhiteSpace(preimageHex)) return Fail("--sign requires a hex preimage");
            byte[] preimage;
            try { preimage = Convert.FromHexString(preimageHex.Trim()); }
            catch { return Fail("the preimage is not valid hex"); }
            if (preimage.Length != 32) return Fail($"the preimage must be 32 bytes, got {preimage.Length}");

            byte[] sig = ecdsa is not null
                // Rfc3279DerSequence: ASN.1 DER, which is what ecdsa.VerifyASN1 expects. The default
                // overload returns raw r||s and would be refused.
                ? ecdsa.SignHash(preimage, DSASignatureFormat.Rfc3279DerSequence)
                : rsa!.SignHash(preimage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Console.WriteLine(Convert.ToHexString(sig).ToLowerInvariant());
            return 0;
        }

        default:
            return Fail($"unknown mode {mode}");
    }
}
catch (CryptographicException ex)
{
    // A cancelled PIN prompt, a removed card, or a key the user cannot use all land here.
    return Fail($"the certificate store refused to sign: {ex.Message}");
}
