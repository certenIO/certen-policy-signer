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

**Test your policy engine.** Sends one synthetic decision request to a URL you type and checks the reply
against the contract. This is the panel most integrators use most, because wiring an engine fails in a
handful of predictable ways — wrong path, non-JSON body, a `decision` value that is not one of the three,
a MAC computed over re-serialized JSON instead of the bytes on the wire — and every one of them shows up
in production as the same unhelpful symptom: *the signer never signs anything*. The tester names which
rule was broken.

**Recent decisions.** The audit trail: what was decided, what vote was cast, and your engine's own stated
reason, stored verbatim beside the transaction.

**Key page governance** *(only with `GOVERNANCE_KEY` set)*. Rotate, add, or remove keys as typed
operations. The signer builds the transaction itself, forces the principal to its own key page, signs what
it built, and confirms the change on chain before replying — there is no endpoint that signs opaque bytes.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SIGNER_URL` | `http://127.0.0.1:8080` | The signer's health/admin listener |
| `ADMIN_API_KEY` | — | Required for anything beyond basic status |
| `GOVERNANCE_KEY` | — | Enables key-page operations; deliberately separate from the admin key |
| `PORT` | `8099` | Console port |
| `BIND` | `127.0.0.1` | Console bind address |

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
