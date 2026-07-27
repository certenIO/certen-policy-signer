/**
 * Quickstart — the whole thing, live, in about eight minutes.
 *
 *   npx tsx scripts/quickstart.ts
 *
 * It provisions its own throwaway identities on a public test network (funded from the faucet — no real
 * value, no pre-existing account, nothing to clean up), runs the real signer as a child process against
 * the real reference policy engine, and walks one transaction through each of the four outcomes.
 *
 * WHAT IT PROVES, and why each one matters:
 *
 *   1. APPROVE  — the engine says yes, the signer signs, the transaction EXECUTES.
 *   2. DENY     — the engine says no, the signer casts a reject vote, the transaction DIES.
 *   3. OUTAGE   — the engine is down. The signer signs NOTHING and the transaction stays pending.
 *                 This is the one to watch: an outage is not a yes. Take the endpoint away and
 *                 transactions stall — they never sail through.
 *   4. PENDING  — the engine answers "not yet" for several polls, then approves. The signer withholds
 *                 the whole time, then signs. Nothing is spent while waiting.
 *
 * Every result is a real, independently checkable fact on a public ledger. Nothing is mocked: the
 * signature is a genuine Ed25519 signature over the genuine Accumulate preimage, and the network — not
 * this script — decides whether to accept it.
 *
 * The shape being demonstrated: a transaction NAMES your key book as a required authority, so Accumulate
 * holds it pending until you act. The submitter needs no cooperation from you to do that, and you need
 * no change to your systems to gate it.
 */
import { spawn, ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ENDPOINT, fundLite, createOrg, createPrincipal, writeIntent, writeConfig,
  txState, sleep, spawnDaemon, kill, raw, Org, Principal,
} from './verify/_lib.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
const ENGINE_PORT = 9399;
const HEALTH_PORT = 18399;
const POLL_SECONDS = 8;

const line = (s = '') => console.log(s);
const rule = (t: string) => {
  line('');
  line('══════════════════════════════════════════════════════════════════════════');
  line(`  ${t}`);
  line('══════════════════════════════════════════════════════════════════════════');
};

const kids: ChildProcess[] = [];
const cleanup = () => kids.forEach(kill);
process.on('SIGINT', () => { cleanup(); process.exit(1); });

/** Start the reference policy engine in one of its modes. */
function startEngine(mode: string): ChildProcess {
  const c = spawn(process.execPath, ['examples/policy-engine.mjs'], {
    env: { ...process.env, PORT: String(ENGINE_PORT), POLICY_MODE: mode },
  });
  c.stdout?.on('data', (d) => process.stdout.write(`      [engine] ${String(d).trimEnd()}\n`));
  kids.push(c);
  return c;
}

/** Render the signer's log lines as something a human can follow. */
function renderSignerLine(parsed: any, rawLine: string): string | null {
  const msg = parsed?.msg ?? rawLine;
  const pick: Record<string, string> = {
    'discovered pending intent; our book is a required authority': 'discovered a pending transaction naming our key book',
    'requesting decision from policy engine': `asking the policy engine: "${parsed?.action ?? ''}"`,
    'policy denied': 'the engine said DENY',
    'policy engine has not decided yet; withholding signature and will retry': 'the engine said PENDING — withholding, will ask again',
    'policy decision failed': `could not reach the engine (${parsed?.err ?? '?'}) — withholding, will retry`,
    'vote submitted': `signed and submitted a ${parsed?.vote?.toUpperCase?.() ?? ''} vote`,
  };
  const friendly = pick[msg];
  if (!friendly) return null;
  return `      [signer] ${friendly}`;
}

/**
 * Run one scenario: write a transaction naming the org's book as an authority, then watch what the
 * signer does about it for up to `waitSeconds`.
 */
async function scenario(opts: {
  title: string;
  engineMode: string;
  amountWei: string;
  expect: string;
  expectExplanation: string;
  waitSeconds: number;
  org: Org;
  principal: Principal;
  configPath: string;
}): Promise<boolean> {
  rule(opts.title);

  const engine = startEngine(opts.engineMode);
  await sleep(700);

  const log: string[] = [];
  let current: string | null = null;
  const daemon = spawnDaemon(opts.configPath, log, () => current, renderSignerLine);
  kids.push(daemon);
  await sleep(2500);

  line(`  A transaction is submitted naming ${opts.org.book} as a required authority.`);
  const w = await writeIntent(opts.principal, { authorities: [opts.org.book], amountWei: opts.amountWei });
  if (!w.ok) throw new Error(`could not write the transaction: ${w.error}`);
  current = w.hash;
  line(`  tx ${w.hash}`);
  line(`  Accumulate is holding it PENDING — it cannot execute until we act.`);
  line('');

  // Poll the chain rather than sleeping a fixed amount: the test network's pace varies.
  let state = 'pending';
  const deadline = Date.now() + opts.waitSeconds * 1000;
  while (Date.now() < deadline) {
    await sleep(4000);
    state = await txState(w.hash, opts.principal.dataPrincipal);
    if (state === 'delivered' || state === 'rejected') break;
  }

  kill(daemon);
  kill(engine);
  await sleep(400);

  const ok = state === opts.expect;
  line('');
  line(`  RESULT: ${state.toUpperCase()}   (expected ${opts.expect.toUpperCase()})  ${ok ? '✅' : '❌'}`);
  line(`  ${opts.expectExplanation}`);
  return ok;
}

async function main() {
  rule('QUICKSTART — a policy engine gating real signatures on a live network');
  line(`  network: ${ENDPOINT}`);
  line('  Provisioning throwaway identities from the faucet. This takes a few minutes.');
  line('');

  const tmp = mkdtempSync(join(tmpdir(), 'signer-quickstart-'));
  const configPath = join(tmp, 'signer.yaml');

  try {
    const f = await fundLite();
    const stamp = Date.now();
    // Two identities: the ORG whose authority is required (us), and the SUBMITTER who initiates.
    const org = await createOrg(f, `acc://qs-org-${stamp}.acme`, 0x21, '400000000');
    const principal = await createPrincipal(f, `acc://qs-sub-${stamp}.acme`, 0x22);

    writeConfig(configPath, {
      orgId: 'quickstart',
      oPage: org.page,
      oSeedHex: Buffer.from(org.key.seed).toString('hex'),
      enginePort: ENGINE_PORT,
      healthPort: HEALTH_PORT,
      interval: POLL_SECONDS,
      storePath: join(tmp, 'state.json'),
    });

    line('');
    line(`  org (authority)  ${org.page}`);
    line(`  submitter        ${principal.dataAccount}`);

    const results: Array<[string, boolean]> = [];

    results.push(['approve', await scenario({
      title: '1/4  APPROVE — the engine says yes',
      engineMode: 'approve', amountWei: '4000', expect: 'delivered',
      expectExplanation: 'The signer added our signature and the transaction executed on chain.',
      waitSeconds: 90, org, principal, configPath,
    })]);

    results.push(['deny', await scenario({
      title: '2/4  DENY — the engine says no',
      engineMode: 'deny', amountWei: '4001', expect: 'rejected',
      expectExplanation: 'The signer cast a REJECT vote. The transaction is dead — not stalled, decided.',
      waitSeconds: 90, org, principal, configPath,
    })]);

    results.push(['outage', await scenario({
      title: '3/4  OUTAGE — the engine is down (the important one)',
      engineMode: 'fail', amountWei: '4002', expect: 'pending',
      expectExplanation:
        'The signer signed NOTHING and the transaction is still pending. A failure is never an approval:\n' +
        '  taking the policy engine away stalls transactions, it does not release signatures.',
      waitSeconds: 45, org, principal, configPath,
    })]);

    results.push(['pending', await scenario({
      title: '4/4  PENDING — the engine needs time, then approves',
      engineMode: 'pending', amountWei: '4004', expect: 'delivered',
      expectExplanation:
        'The engine answered "not yet" for several polls while the signer withheld, then approved —\n' +
        '  and only then was anything signed. This is how a human approval or step-up challenge works.',
      waitSeconds: 150, org, principal, configPath,
    })]);

    rule('SUMMARY');
    for (const [name, ok] of results) line(`  ${ok ? '✅' : '❌'}  ${name}`);
    const allOk = results.every(([, ok]) => ok);
    line('');
    if (allOk) {
      line('  All four outcomes behaved as specified, on a live public ledger.');
      line('');
      line('  Next: replace checkPolicy() in examples/policy-engine.mjs with your own engine.');
      line('  That one function is the entire integration — see docs/INTEGRATION.md.');
    } else {
      line('  Something did not match. The test network can be slow — re-running usually settles it.');
      line('  If a result is consistently wrong, that is a real finding; please open an issue.');
    }
    process.exitCode = allOk ? 0 : 1;
  } finally {
    cleanup();
    rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch((e) => {
  cleanup();
  console.error('\nquickstart failed:', e?.message ?? e);
  process.exit(1);
});
