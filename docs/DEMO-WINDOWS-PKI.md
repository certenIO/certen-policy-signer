# Demo — a bank employee signs with the certificate they already have

**What a viewer sees.** An employee's existing Windows certificate — the kind Microsoft ADCS issues
to every member of staff — becomes an approver on an Accumulate key page, reviews a payment in the
approval console, and its signature is what authorises the transaction on a public network. No wallet
is installed, no key is generated for them, and no key material leaves the certificate store.

**What makes it credible.** Every claim is checkable on-chain afterwards, and the demo reads the
result back off the network rather than reporting what it believes it did.

---

## 0 · What this rests on, and what it does not

| Proven, on Kermit | Status |
|---|---|
| A Windows certificate-store key signs an Accumulate transaction | ✅ `delivered`, `type=ecdsaSha256` |
| An identity founded on a certificate, with no Ed25519 key at all | ✅ page `version 1`, one key, the certificate |
| Enrolment the organisation cannot fake — the protocol holds the seat until the employee's key co-signs | ✅ `scripts/verify/roster-enrolment.ts` |
| The signer votes with a PKI key on a page holding only that key | ✅ `scripts/verify/pki-ecdsa-vote.ts` |
| RSA-2048 (what ADCS actually issues) through the same path | ✅ `test/windows-cert-store.test.ts` |

**Proven as of 2026-09-05, and you may now claim it:** the console's *approve* button IS what causes
that employee's certificate to sign. A person approved in the console and their certificate signed on
Kermit —
`acc://60c82b865842359f82ef7940206e72227e114efda6ef9c7b77530e2ac6d37a30@loopa1788597054633.acme/data`,
`delivered (201)`, an `ecdsaSha256` signature from a page whose only key is her certificate. Reproduce
it with `scripts/verify/pki-console-loop.ts`. This paragraph previously said the opposite; it was
true until T29 closed the join between "who approved" and "whose key signed".

**Also proven as of 2026-09-05, and you may claim this too:** *two* approvers through that same loop.
Two employees approved in the console and two different certificates signed; the transaction executed
only once both had.

```
acc://5770d71481570dd61f5d54afbe95266437b58be18be57e130c1b4b8eed532588@twoa1788601803711.acme/data
  status      delivered
  signatures  ecdsaSha256  2cfd3f34…679e  <- Alice
              ecdsaSha256  e629f477…c9c1  <- Bob
  team page   acc://twob1788601803711.acme/book/1   threshold 2, exactly those two key hashes
```

Reproduce with `scripts/verify/pki-console-loop-two.ts`. Worth saying out loud in the room, because it
is the part a bank cares about most: **Alice's certificate is what seated Bob's and raised the
threshold to 2.** No software key ever acted on that page, from founding onward. This paragraph
previously said two approvers were unproven; that was true until the run above.

**Also:** the public explorer cannot render a PKI-signed transaction — its bundled SDK throws
`15 is not a key signature type`. Verify through the API or the console's evidence document instead.
Do not put a viewer in front of the explorer for this.

---

## 1 · Prerequisites

- **Windows**, .NET 9 SDK, Node 20+.
- A certificate in `Cert:\CurrentUser\My` with a private key. In a real deployment this is the
  employee's ADCS-issued certificate or their PIV/CAC card. For a demo, create a stand-in:

  ```powershell
  $c = New-SelfSignedCertificate -Type Custom -Subject 'CN=Alice Okonkwo' `
        -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 `
        -KeyUsage DigitalSignature -Provider 'Microsoft Software Key Storage Provider' `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(30)
  $c.Thumbprint
  ```

  > **Thirty days, not two.** This said `AddDays(2)`, and a stand-in certificate made while preparing
  > is expired by the meeting it was made for — a failure that arrives in the room, in front of the
  > client, looking like the product is broken. Thirty is still short enough to be obviously a prop.
  > Check before you present: `(Get-Item Cert:\CurrentUser\My\<THUMBPRINT>).NotAfter`.

  `NonExportable` matters: it makes the demo honest. The key cannot be copied out, which is why an
  agent is required rather than a convenience.

  > **Use a YubiKey in PIV mode, not a government CAC,** for anything a client sees. A CAC works
  > technically, but DoD acceptable-use policy restricts it to official purposes and a government
  > credential is the wrong prop for a bank meeting.

- Build the agent once:

  ```powershell
  dotnet build agent/windows-cert-store/certen-cert-agent.csproj -c Release
  ```

---

## 2 · Show that the certificate can sign at all

Thirty seconds, and it makes everything after it concrete:

```powershell
$agent = "agent\windows-cert-store\bin\Release\net9.0\certen-cert-agent.exe"
& $agent --thumbprint <THUMBPRINT> --describe      # RSA-2048 rsaSha256
& $agent --thumbprint <THUMBPRINT> --public-key    # 294 bytes of PKIX DER
```

**Say:** *sha256 of that public key is the entry that goes on the key page. That is the whole of
enrolment — no new credential, no key ceremony. The bank's CA already bound this key to Alice.*

---

## 3 · Point the signer at it

```yaml
signer:
  provider: windows-cert-store
  windows:
    thumbprint: "<THUMBPRINT>"
    agent_path: "agent/windows-cert-store/bin/Release/net9.0/certen-cert-agent.exe"
```

**Say:** *there is no key in this configuration. There is a thumbprint. The private key stays in the
certificate store — on a card, it cannot leave at all.*

The signature type is read from the certificate, not configured, so the same block works whether the
employee's credential is RSA or ECDSA. That matters more than it sounds: a corporate CA usually
issues RSA, while a YubiKey you provision yourself is usually P-256.

---

## 4 · The two halves to demonstrate

**Half one — enrolment the organisation cannot fake.**

```bash
npx tsx scripts/verify/roster-enrolment.ts
```

The organisation proposes the seat; the network holds it pending; step 5 waits and the seat still
does not exist; only when the employee's own certificate signs does it execute.

**Say:** *the bank cannot add someone as an approver on its own. `update_key_page.go` requires every
new delegate to sign the transaction that adds them. That is not our policy — it is the protocol's,
and we could not switch it off if a customer asked.*

**Half two — the approval, in the console.**

```bash
npm run demo        # in certen-approval-console, with a Postgres up
```

Sign in, open the queue, read a payment in business language, approve it with a reason. Then open the
evidence document for it.

**Say:** *the console decides and records why. Note what the document claims and what it declines to
claim — it says the approver's identity is a record this console kept, not a proof. That distinction
is what an auditor will ask about, and it is already written down.*

---

## 5 · Verify on-chain, in front of them

```powershell
$body = @{jsonrpc='2.0';id=1;method='query';params=@{scope='<TXID>'}} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri 'https://kermit.accumulatenetwork.io/v3' -Method Post `
  -Body $body -ContentType 'application/json' | ConvertTo-Json -Depth 8
```

Look for `"status": "delivered"` and `"type": "ecdsaSha256"` (or `rsaSha256`).

**One thing that looks alarming and is not:** for `updateKeyPage` the result is
`{"type":"unknown"}`. That is what an empty result serialises to — `UpdateKeyPage.Execute` returns no
result object — and it appears identically on Ed25519-signed transactions. The status is
`delivered (201)`. A `writeData` returns a typed result with an `entryHash` if you would rather
demonstrate on one of those.

---

## 6 · The questions you will be asked

**"Where is the private key?"** In the certificate store, in its key-storage provider. On a card, in
the card. The signer holds a thumbprint and calls an agent; it never sees key material. That is why
the agent exists rather than being a convenience.

**"What if the employee leaves?"** Revocation removes the seat, and the next vote from that key
fails. Demonstrated in `roster-enrolment.ts`.

**"Can you prove the person approved, not just their key?"** Not today, and the product says so
rather than implying otherwise. The key proves the credential; binding the living person is the Trust
Stamp biometric rung (§F7), where the strongest form puts Trust Stamp's key book on the transaction
as a second required authority the bank cannot suppress.

**"Does this need a new PKI?"** No. It needs the one they have. `sha256` of a certificate's public
key is the page entry, and that is the entire integration.
