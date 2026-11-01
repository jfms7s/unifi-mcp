/**
 * One-off live check that the console's legacy command endpoints accept the API
 * key. It changes the real network, so it is never run by tests or CI.
 *
 *   set -a; . ~/.config/unifi-mcp/.env; set +a
 *   UNIFI_URL=https://192.168.10.1 npx tsx scripts/spike-writes.ts
 *
 * The only writes: set-locate then unset-locate on the access point, and
 * block-sta then immediately unblock-sta on one idle smart light on the IoT or
 * a guest network. If no client passes every rule the block test is skipped.
 * Prints only a network name, a type hint and `client-N`; the client's MAC shows
 * up in exactly one place, the UNBLOCK FAILED line the owner must act on.
 */
import { loadConfig } from '../src/config.js';
import { createUnifiHttpClient } from '../src/http/client.js';
import { describeError, UnifiApiError } from '../src/http/errors.js';
import { createLegacyApi, type LegacyApi } from '../src/unifi/legacy.js';
import { isVerifiedUnblocked, once, pickClient, withNetwork } from './spike-rules.js';

const REF = 'default';
const LOCATE_SECONDS = 10;
const UNBLOCK_RETRIES = 3;
const RETRY_DELAY_MS = 2_000;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function outcome(error: unknown): string {
  const status = error instanceof UnifiApiError && error.status ? `HTTP ${error.status}, ` : '';
  return `rejected (${status}${describeError(error)})`;
}

async function step(label: string, run: () => Promise<void>): Promise<boolean> {
  try {
    await run();
    console.log(`${label}: rc ok`);
    return true;
  } catch (error) {
    console.log(`${label}: ${outcome(error)}`);
    return false;
  }
}

/** rest/user's `blocked` for the MAC; undefined when it is missing or cannot be read. */
async function blockedState(api: LegacyApi, mac: string): Promise<boolean | undefined> {
  try {
    return (await api.knownClients(REF)).find((c) => c.mac === mac)?.blocked;
  } catch (error) {
    console.log(`rest/user check: ${outcome(error)}`);
    return undefined;
  }
}

/** unblock-sta, then confirm it in rest/user; retried, and only a confirmed unblock is success. */
async function unblock(api: LegacyApi, mac: string): Promise<boolean> {
  for (let attempt = 0; attempt <= UNBLOCK_RETRIES; attempt++) {
    if (attempt > 0) await sleep(RETRY_DELAY_MS);
    await step(`unblock-sta attempt ${attempt + 1}`, () =>
      api.cmd(REF, 'stamgr', { cmd: 'unblock-sta', mac }),
    );
    const blocked = await blockedState(api, mac);
    console.log(`rest/user blocked after unblock-sta: ${String(blocked)}`);
    if (isVerifiedUnblocked(blocked)) return true;
  }
  return false;
}

/** Each cleanup resolves true when it left nothing for the owner to fix by hand. */
const cleanups: (() => Promise<boolean>)[] = [];
/** One run shared by the normal path, the signal handlers and main's catch; false means a client may still be blocked. */
const runCleanups = once(async (): Promise<boolean> => {
  let safe = true;
  for (const cleanup of cleanups) safe = (await cleanup()) && safe;
  return safe;
});
/** Waits for the shared cleanup run, then exits with `code`, or 2 when it left a client blocked. */
async function exitAfterCleanup(code: number): Promise<never> {
  return process.exit((await runCleanups()) ? code : 2);
}
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    console.error(`${signal}: undoing changes before exit`);
    void exitAfterCleanup(130);
  });
}

async function locateTest(api: LegacyApi, mac: string): Promise<boolean> {
  // A timed-out set-locate may still have landed, so unset-locate is always sent, once.
  let unset = false;
  const undo = async (): Promise<boolean> => {
    if (unset) return true;
    unset = true;
    await step('unset-locate', () => api.cmd(REF, 'devmgr', { cmd: 'unset-locate', mac }));
    return true;
  };
  cleanups.push(undo);
  const set = await step('set-locate', () => api.cmd(REF, 'devmgr', { cmd: 'set-locate', mac }));
  if (set) {
    console.log(`locating for ${LOCATE_SECONDS}s`);
    await sleep(LOCATE_SECONDS * 1_000);
  }
  await undo();
  return set;
}

async function blockTest(api: LegacyApi, mac: string, label: string): Promise<boolean> {
  let ok = false;
  try {
    // Registered just before the command goes out: a reply that times out may still have landed.
    cleanups.push(async () => {
      if (await unblock(api, mac)) return true;
      console.error(`UNBLOCK FAILED for ${label} — owner must unblock ${mac} in the UniFi app`);
      return false;
    });
    ok = await step('block-sta', () => api.cmd(REF, 'stamgr', { cmd: 'block-sta', mac }));
    if (ok)
      console.log(`rest/user blocked after block-sta: ${String(await blockedState(api, mac))}`);
  } finally {
    if (!(await runCleanups())) process.exit(2);
  }
  return ok;
}

async function main(): Promise<void> {
  const api = createLegacyApi(createUnifiHttpClient(loadConfig(), { timeoutMs: 15_000 }));
  const [devices, stations, networks] = await Promise.all([
    api.devicesBasic(REF),
    api.stations(REF),
    api.networkConf(REF),
  ]);

  const ap = devices.find((d) => d.type === 'uap');
  const target = pickClient(withNetwork(stations, new Map(networks.map((n) => [n._id, n.name]))));
  console.log(`access point: ${ap ? 'found' : 'none'}`);
  console.log(
    target
      ? `client: client-${target.index}, smart light, network ${target.network}`
      : 'client: none passes every rule, block test skipped',
  );

  let allOk = true;
  if (ap) allOk = (await locateTest(api, ap.mac)) && allOk;
  else allOk = false;
  if (target) allOk = (await blockTest(api, target.station.mac, `client-${target.index}`)) && allOk;
  process.exit(allOk ? 0 : 1);
}

main().catch(async (error: unknown) => {
  console.error(`spike failed: ${describeError(error)}`);
  await exitAfterCleanup(1);
});
