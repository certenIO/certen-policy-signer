# Accumulate and Certen — a primer

*For teams integrating with Certen for the first time. No blockchain background assumed. Nothing here is
required reading to run the software; it is here so that when you read the integration docs, you know what
the pieces are.*

---

## Accumulate — the ledger underneath

Accumulate is a public blockchain built around **identity** rather than around addresses. Instead of a
wallet being a string of hex, an organization owns an **ADI** (Accumulate Digital Identifier) — a
human-readable, hierarchical name like `acc://trust-stamp.acme`. Everything that organization owns lives
underneath that name as its own account: `acc://trust-stamp.acme/tokens`, `acc://trust-stamp.acme/orders`,
and so on. Because the identity is the root object rather than a key, the keys underneath it can be added,
removed, and rotated without the identity changing or anyone needing to be told a new address.

Authority under an ADI is a two-level structure. A **key book** is the authority; a **key page** inside it
holds the actual keys. A page has a **threshold** — "2 of these 4 keys" — and a book can hold several pages
at different priority levels, so a routine page might need three signatures while a higher-priority page
satisfies the book on its own (that is how a break-glass or escalation seat is built). Keys on a page may be
different signature types — Ed25519, ECDSA/secp256k1, RSA, BTC- and ETH-style keys — which is what lets an
existing corporate HSM, an Ethereum-style key, and a plain software key sit side by side in the same
approval group. A key page entry can also be a **delegation** to another key book entirely, so one
organization's book can be a required approver inside another's, and hierarchies nest arbitrarily.

The behavior that everything else builds on: **Accumulate holds a transaction PENDING until every required
authority has signed it.** When someone submits a transaction and names your key book as a required
authority, the network will not execute it without you. It is not queued in someone's database awaiting a
callback — the ledger itself refuses to proceed, indefinitely, until your signature arrives or a required
authority votes to reject and kills it. That pending state is the hook that policy enforcement plugs into,
and it is enforced by the validators, not by an application.

---

## Certen — proof-gated execution across chains

Certen uses Accumulate as a **control plane** for actions that settle somewhere else. The pattern: you write
an **intent** to Accumulate describing an action on another network — "transfer 4,000 wei to `0xBe00…` on
Ethereum" — and that intent is an ordinary Accumulate transaction, which means it inherits everything above.
It sits PENDING until the authorities named on it sign. Nothing has moved on Ethereum yet. Authorization
happens first, on a ledger, in public, with a named multi-party approval structure; settlement happens
afterward. The value of splitting it that way is that the decision to move funds is auditable and
multi-party *before* a single wei moves, rather than being reconstructed from logs afterward.

Once an intent is fully authorized, Certen executes it — and this is the part that distinguishes Certen from
a relayer or a bridge. A relayer asks you to trust that it faithfully carried out what you approved. Certen
instead produces a **proof** that the exact call it executed is the exact call that was authorized, and the
destination chain verifies that proof before executing. The cycle runs in nine phases. Briefly: the intent is
canonicalized into four blobs whose combined hash is the **OperationID**; a lite client produces an inclusion
proof binding that intent to Accumulate's state; an independent validator set **BLS-signs the OperationID**;
the signed attestation is committed in a BFT consensus round; those commitments are folded into a small
Merkle root; and a contract on the destination chain verifies the aggregate signature — as a ZK-SNARK, so
verification is cheap — before it will let the call run at all. A wrong call does not get executed and
reverted; it never executes.

The last three phases close the loop the other way. An observer watches the destination chain for the actual
result; the validator set **BLS-signs that result too** — a second, domain-separated signing event, so an
attestation about an outcome can never be replayed as an authorization — and the outcome is written back to
Accumulate as a transaction. The result is a single audit chain, on a public ledger, running from *"who
approved this and under what rule"* through *"here is the proof the network verified"* to *"here is what
actually happened on the other chain."* One of the two BLS events proves the call was authorized; the other
proves what it did. On the destination side, each ADI owns a deterministic **CertenAccount** — a smart
account, derived from the identity, at the same address on every EVM chain — so an Accumulate identity has a
stable on-chain presence to be the `msg.sender` of the calls it authorizes. Certen runs against Ethereum and
the major L2s, with the same anchor contract ported to several non-EVM chains.

What this buys an integrator is narrower than "a blockchain," and more useful. **Any decision your business
already makes off-chain can become a cryptographic precondition for an on-chain action.** A biometric
re-authentication, a fraud score, a sanctions check, a spending limit, a shipment confirmation, a human with
a button — name your key book as an authority on the transaction, and that decision is now enforced by the
ledger rather than by convention. Nobody can route around it, because the network will not execute the
transaction without your signature. And critically, the party *submitting* the transaction does not have to
change how they build it; adding a policy gate is a change to who is named as an authority, not a change to
the protocol.

That is where the **headless policy-engine signer** comes in, and it is the only Certen component most
integrators actually run. It is a small service you host, holding your key, that watches Accumulate for
pending transactions naming your key book, decodes what each one does, asks *your* policy engine over one
HTTP POST, and signs only on an explicit `approve`. It is deliberately not custodial and deliberately dumb:
it has no opinion about your rules, and every failure mode — a timeout, a crash, a malformed reply, an
unreachable engine — withholds the signature rather than granting it. An outage can delay a transaction; it
can never authorize one.

---

## How the pieces line up

| | |
|---|---|
| **Accumulate** | The identity and authorization ledger. Holds transactions PENDING until required authorities sign. |
| **Certen intent** | An Accumulate transaction describing an action on another chain. Authorized first, settled second. |
| **Certen proof cycle** | Nine phases, two independent validator signing events, verified on the destination chain before execution and written back to Accumulate afterward. |
| **CertenAccount** | The identity's smart account on the destination chain — deterministic, same address across EVM chains. |
| **Headless policy-engine signer** | The piece you run. Your key, your policy engine, fail-closed. This is the integration surface. |

**Where to go next:** [`../README.md`](../README.md) for what the signer is and a ten-minute local run,
then [`INTEGRATION.md`](INTEGRATION.md) for the decision contract your policy engine implements.
