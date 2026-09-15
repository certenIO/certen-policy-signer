/**
 * Generate the test key pairs INSIDE the SoftHSM token, through pkcs11js. The private keys are created
 * non-extractable and sensitive (except the two deliberately wrong ones the suite must refuse), so no
 * private key material exists anywhere but the token. Labels are FICTIONAL.
 */
import pkcs11js from 'pkcs11js';

const { PKCS11 } = pkcs11js;
const CKA = { CLASS: 0x0, TOKEN: 0x1, PRIVATE: 0x2, LABEL: 0x3, SENSITIVE: 0x103, SIGN: 0x108, VERIFY: 0x10a, EXTRACTABLE: 0x162, EC_PARAMS: 0x180 };
const CKM_EC_KEY_PAIR_GEN = 0x1040;
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055;
const P256 = Buffer.from('06082a8648ce3d030107', 'hex');   // OID prime256v1
const ED25519 = Buffer.from('06032b6570', 'hex');           // OID 1.3.101.112

const { PKCS11_MODULE, PKCS11_TOKEN_LABEL, PKCS11_PIN } = process.env;
const p = new PKCS11();
p.load(PKCS11_MODULE);
p.C_Initialize();
try {
  const slot = p.C_GetSlotList(true).find((s) => p.C_GetTokenInfo(s).label.trim() === PKCS11_TOKEN_LABEL);
  if (!slot) throw new Error(`no token ${PKCS11_TOKEN_LABEL}`);
  const session = p.C_OpenSession(slot, 0x2 | 0x4);
  p.C_Login(session, 1, PKCS11_PIN);

  const gen = (label, curve, { extractable = false, sensitive = true } = {}) => {
    const ed = curve === 'ed25519';
    p.C_GenerateKeyPair(
      session,
      { mechanism: ed ? CKM_EC_EDWARDS_KEY_PAIR_GEN : CKM_EC_KEY_PAIR_GEN },
      [
        { type: CKA.TOKEN, value: true }, { type: CKA.LABEL, value: label }, { type: CKA.VERIFY, value: true },
        { type: CKA.EC_PARAMS, value: ed ? ED25519 : P256 },
      ],
      [
        { type: CKA.TOKEN, value: true }, { type: CKA.PRIVATE, value: true }, { type: CKA.LABEL, value: label },
        { type: CKA.SIGN, value: true }, { type: CKA.SENSITIVE, value: sensitive }, { type: CKA.EXTRACTABLE, value: extractable },
      ],
    );
    console.log(`[provision] generated ${curve} key "${label}" in the token (extractable=${extractable}, sensitive=${sensitive})`);
  };

  gen('machine-orchid-ed25519-fictional', 'ed25519');
  gen('machine-orchid-p256-fictional', 'p256');
  gen('extractable-p256-fictional', 'p256', { extractable: true });
  gen('insensitive-p256-fictional', 'p256', { sensitive: false });

  p.C_Logout(session);
  p.C_CloseSession(session);
} finally {
  p.C_Finalize();
}
