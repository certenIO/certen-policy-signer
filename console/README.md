# Operator console

A small, dependency-free console for running the signer: watch it, stop it, check your policy engine is
wired correctly, and manage the key page.

```bash
ADMIN_API_KEY=<your admin key> SIGNER_URL=http://127.0.0.1:8080 npm run console
# open http://127.0.0.1:8099
```

Two files, both meant to be edited: [`server.mjs`](server.mjs) (the backend, ~200 lines) and
[`index.html`](index.html) (the whole UI). No build step, no framework, no dependencies.

## What it does

**Status and emergency stop.** Health, discovery liveness, and whether signing is paused — plus the pause
button. Pause halts *everything*, including reject votes, because a reject is still a signature.

On a signer watching more than one key page, this panel also breaks discovery down **per page**, stalled
ones first, with each page's last success. The aggregate is not actionable on a fleet: twelve agents
reporting one boolean tells you something stopped, not which agent. `/healthz` also names the stalled pages
in `reasons` (`poller_stalled:acc://…`), so an alert built on the reason string is specific too.

**Test your policy engine.** Sends one synthetic decision request to a URL you type and checks the reply
against the contract. This is the panel most integrators use most, because wiring an engine fails in a
handful of predictable ways — wrong path, non-JSON body, a `decision` value that is not one of the three,
a MAC computed over re-serialized JSON instead of the bytes on the wire — and every one of them shows up
in production as the same unhelpful symptom: *the signer never signs anything*. The tester names which
rule was broken.

**Fleet awareness.** Both decision tables carry a **Page** column, and a filter above the work queue scopes
every table to one page. Both appear **only when this signer watches more than one page** — a column that
always says the same thing is worse than no column, so a single-scope console looks exactly as it did
before. Page filtering is client-side over rows already fetched (status filtering is server-side, since that
decides which rows are fetched at all).

**Waiting on a decision.** Everything the signer has discovered and nobody has decided yet, with how long
each has been sitting there. An empty list is the healthy state; a growing one means your engine has stopped
answering. This is `GET /v1/requests?status=awaiting_policy` — filtered server-side, so it stays accurate on
a busy signer instead of showing whatever falls inside the recent window.

**Recent decisions.** The audit trail: what was decided, what vote was cast, and your engine's own stated
reason, stored verbatim beside the transaction.

**Awaiting your approval** *(only when the escalation variables below are set)*.
The disputes the automated seats could not settle, with the split, the rule that
stopped it, and a Sign button. Signing adds your signature on **your own key
page** — higher priority than the routine one, so it satisfies the book alone and
completes work the routine page could never finish.

This panel is **one worked pattern, not the general mechanism** — it assumes the escalation queue lives in
your policy engine and that you sign through the gateway, which is a specific architecture. If yours differs,
build your own against `GET /v1/requests?status=awaiting_policy`, which is the general form and what the
panel above it uses.

The key is never held here. `CERTEN_KEYSTORE` points at an encrypted file, and
the passphrase is typed per signature, used once, and discarded — not cached, not
logged, never written down. Nothing can sign while you are away, which is the
only reason an escalation seat is worth separating from the automated ones. The
list is reconciled against the chain first, so work already settled some other
way is not offered to you again.

**Key page governance** *(only with `GOVERNANCE_KEY` set)*. Rotate, add, or remove keys as typed
operations. The signer builds the transaction itself, forces the principal to its own key page, signs what
it built, and confirms the change on chain before replying — there is no endpoint that signs opaque bytes.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SIGNER_URL` | `http://127.0.0.1:8080` | The signer's health/admin listener |
| `ADMIN_API_KEY` | — | Required for anything beyond basic status |
| `GOVERNANCE_KEY` | — | Enables key-page operations; deliberately separate from the admin key |
| `PORT` | `8099` | Console port. The signer's own default health port is 8080, so the two do not clash unless a config moves one onto the other. |
| `BIND` | `127.0.0.1` | Console bind address |

For the **Awaiting your approval** panel (all five, or the panel stays hidden
rather than offering a button that cannot work):

| Variable | Meaning |
|---|---|
| `POLICY_URL` | your policy engine — where the queue lives |
| `POLICY_TOKEN` | its `APPROVAL_TOKEN` |
| `CERTEN_KEYSTORE` | encrypted keystore holding your escalation seat |
| `CERTEN_API_KEY` | gateway API key |
| `CERTEN_IDENTITY` / `CERTEN_PAGE` | the panel ADI and **your** key page |

## Security

**This is an operator tool, like `kubectl`.** It holds credentials that can pause your signing and
reorganize your key page.

It has **no authentication of its own**, and that is deliberate: a password field would imply a security
boundary this does not have. **Reachability is the boundary.** It binds to loopback by default; changing
`BIND` should be a deliberate act, and it warns when you do.

The credentials stay in the server process and are never sent to the browser. The backend exposes an
explicit allowlist of signer operations rather than proxying arbitrary requests — a generic proxy in front
of an admin API means the browser can call anything the credential can, and a browser page is the least
trustworthy component here.

## Customizing it

Adding a panel is two edits:

1. **`server.mjs`** — add an entry to the `ALLOW` list if you need a new signer route, or add an
   `/api/...` handler for something the console should do itself.
2. **`index.html`** — add a `<section class="panel">` and a function that calls it.

Common extensions: point the activity table at your own ticketing system, add a panel that renders your
engine's `evidence` in a domain-specific way, or add whatever health checks your policy engine exposes
alongside the signer's.
