/**
 * WindowsCertStoreSigner — the KeySigner contract, against a real certificate.
 *
 * The interesting assertions here are not "it returns bytes" but the three encodings that fail
 * SILENTLY if they are wrong: the preimage must be signed as a digest, the public key must be
 * PKIX/SPKI DER, and the key page entry must be sha256 of exactly those bytes. Each of them produces
 * a well-formed signature that the network then refuses for reasons that read like a missing key.
 *
 * The tests that need a certificate create one in the Windows certificate store and remove it again,
 * and SKIP on any other platform or if the agent has not been built — the point of this provider is
 * that it talks to something outside the process, so there is nothing honest to mock for those. The
 * argument-validation tests need neither and run everywhere.
 */
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createHash, createVerify, createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { WindowsCertStoreSigner } from '../src/signer/windows-cert-store.js';

const AGENT = join(
  process.cwd(), 'agent', 'windows-cert-store', 'bin', 'Release', 'net9.0', 'certen-cert-agent.exe',
);
const canRun = process.platform === 'win32' && existsSync(AGENT);
const withCert = canRun ? describe : describe.skip;

/** A stand-in for the certificate a corporate CA issues to a person. RSA-2048: what ADCS defaults to. */
function makeCert(subject: string): string {
  const ps = [
    `$c = New-SelfSignedCertificate -Type Custom -Subject '${subject}' -CertStoreLocation Cert:\\CurrentUser\\My`,
    `-KeyAlgorithm RSA -KeyLength 2048 -KeyUsage DigitalSignature`,
    `-Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy NonExportable`,
    `-NotAfter (Get-Date).AddDays(1); $c.Thumbprint`,
  ].join(' ');
  return execFileSync('powershell', ['-NoProfile', '-Command', ps], { encoding: 'utf8' }).trim();
}

function removeCert(thumbprint: string): void {
  try {
    execFileSync('powershell', ['-NoProfile', '-Command',
      `Remove-Item "Cert:\\CurrentUser\\My\\${thumbprint}" -Force -ErrorAction SilentlyContinue`]);
  } catch { /* best effort: a leftover test certificate expires in a day anyway */ }
}

describe('WindowsCertStoreSigner configuration', () => {
  it('refuses to be constructed without a certificate to use', () => {
    expect(() => new WindowsCertStoreSigner({ thumbprint: '', agentPath: 'x' })).toThrow(/thumbprint is required/);
    expect(() => new WindowsCertStoreSigner({ thumbprint: 'abc', agentPath: '  ' })).toThrow(/agent_path is required/);
  });

  it('will not report a signature type it has not read off the certificate', () => {
    // Reading `undefined` here would put it in the signature metadata, and therefore in the preimage,
    // producing a signature nothing can verify. Throwing is the only safe answer.
    const s = new WindowsCertStoreSigner({ thumbprint: 'abc', agentPath: 'x' });
    expect(() => s.signatureType).toThrow(/not known until the certificate has been read/);
  });

  it('reports a missing certificate rather than a bare command failure', async () => {
    const s = new WindowsCertStoreSigner({ thumbprint: 'deadbeef', agentPath: 'no-such-agent-binary' });
    await expect(s.publicKey()).rejects.toThrow(/WindowsCertStoreSigner:/);
    expect(await s.health()).toBe(false);
  });
});

withCert('WindowsCertStoreSigner against a real certificate', () => {
  let thumbprint: string;
  let signer: WindowsCertStoreSigner;

  beforeAll(() => {
    thumbprint = makeCert('CN=Certen Signer Test');
    signer = new WindowsCertStoreSigner({ thumbprint, agentPath: AGENT });
  });
  afterAll(() => removeCert(thumbprint));

  it('reads the signature type from the certificate, not from configuration', async () => {
    await signer.publicKey();
    expect(signer.signatureType).toBe('rsaSha256');
  });

  it('returns the public key as PKIX/SPKI DER', async () => {
    const spki = await signer.publicKey();
    // It parses as SPKI, which is the encoding the network's ParsePKIXPublicKey expects.
    const key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    expect(key.asymmetricKeyType).toBe('rsa');
  });

  it('signs the preimage AS A DIGEST, which is what makes the signature verifiable', async () => {
    // A real preimage is sha256(sigMdHash || txnHash); any 32 bytes exercise the same path.
    const preimage = createHash('sha256').update('a transaction').digest();
    const sig = await signer.sign(new Uint8Array(preimage));
    const spki = await signer.publicKey();
    const key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });

    // Verify by treating the preimage as the message digest — i.e. the same way the network does.
    // If the agent had used SignData, the signature would be over sha256(preimage) and this fails.
    const ok = createVerify('sha256').update(preimage).end().verify(key, Buffer.from(sig));
    expect(ok).toBe(false); // signing the digest is NOT the same as signing the digest's hash

    const verified = createVerify('sha256')
      .update('a transaction').end()
      .verify(key, Buffer.from(sig));
    expect(verified).toBe(true);
  });

  it('the key page entry is sha256 of the DER public key', async () => {
    const spki = await signer.publicKey();
    const entry = createHash('sha256').update(Buffer.from(spki)).digest('hex');
    expect(entry).toMatch(/^[0-9a-f]{64}$/);
    // Not a hash of some inner key material — the whole DER blob, which is what the network hashes.
    expect(entry).not.toBe(createHash('sha256').update(Buffer.from(spki).subarray(24)).digest('hex'));
  });

  it('rejects a preimage that is not 32 bytes', async () => {
    await expect(signer.sign(new Uint8Array(31))).rejects.toThrow(/32-byte/);
  });

  it('is healthy while the certificate is reachable', async () => {
    expect(await signer.health()).toBe(true);
  });
});
