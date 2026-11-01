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
import { createLegacyApi, type LegacyApi, type Station } from '../src/unifi/legacy.js';

const REF = 'default';
const LOCATE_SECONDS = 10;
const UNBLOCK_RETRIES = 3;
const RETRY_DELAY_MS = 2_000;
const IDLE_BYTES_LIMIT = 5_000_000;
const SAFE_NETWORKS = new Set(['IoT']);
const PROTECTED_PREFIX = '192.168.0.';
const DESKTOP_IP = '192.168.10.10';
/** What a candidate must look like: a smart light, the least consequential thing to cut off. */
const LIGHT = /nanoleaf|light|lamp|bulb/i;
/** People's devices, network gear and anything safety-related are never touched. */
const EXCLUDED =
  /phone|iphone|android|pixel|galaxy|samsung|laptop|macbook|mac|workstation|pc|tablet|ipad|watch|ap|switch|gateway|router|camera|cam|doorbell|alarm|smoke|lock|heater|heat|power|meter|cluster|sensor|siren|water|gas|fire|medical/i;

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

function pickClient(stations: Station[], networkNames: Map<string, string>) {
  const named = stations.map((station, index) => ({
    station,
    index,
    network: (station.network_id && networkNames.get(station.network_id)) ?? station.network ?? '',
  }));
  return named.find(({ station: s, network }) => {
    const text = `${s.hostname ?? ''} ${s.name ?? ''} ${s.oui ?? ''}`;
    const ip = s.ip ?? '';
    return (
      (SAFE_NETWORKS.has(network) || s.is_guest === true) &&
      !ip.startsWith(PROTECTED_PREFIX) &&
      ip !== DESKTOP_IP &&
      !s.is_wired &&
      LIGHT.test(text) &&
      !EXCLUDED.test(text) &&
      (s.tx_bytes ?? 0) + (s.rx_bytes ?? 0) < IDLE_BYTES_LIMIT &&
      s.blocked !== true
    );
  });
}

async function isBlocked(api: LegacyApi, mac: string): Promise<boolean | undefined> {
  const user = (await api.knownClients(REF)).find((c) => c.mac === mac);
  return user?.blocked;
}

/** unblock-sta with retries; the caller exits non-zero when this returns false. */
async function unblock(api: LegacyApi, mac: string): Promise<boolean> {
  for (let attempt = 0; attempt <= UNBLOCK_RETRIES; attempt++) {
    if (attempt > 0) await sleep(RETRY_DELAY_MS);
    try {
      await api.cmd(REF, 'stamgr', { cmd: 'unblock-sta', mac });
      return true;
    } catch (error) {
      console.log(`unblock-sta attempt ${attempt + 1}: ${outcome(error)}`);
    }
  }
  return false;
}

async function locateTest(api: LegacyApi, mac: string): Promise<boolean> {
  let ok = await step('set-locate', () => api.cmd(REF, 'devmgr', { cmd: 'set-locate', mac }));
  if (!ok) return false;
  try {
    console.log(`locating for ${LOCATE_SECONDS}s`);
    await sleep(LOCATE_SECONDS * 1_000);
  } finally {
    ok =
      (await step('unset-locate', () => api.cmd(REF, 'devmgr', { cmd: 'unset-locate', mac }))) &&
      ok;
  }
  return ok;
}

async function blockTest(api: LegacyApi, mac: string, label: string): Promise<boolean> {
  let ok = false;
  try {
    ok = await step('block-sta', () => api.cmd(REF, 'stamgr', { cmd: 'block-sta', mac }));
    if (ok) console.log(`rest/user blocked after block-sta: ${String(await isBlocked(api, mac))}`);
  } finally {
    if (!(await unblock(api, mac))) {
      console.error(`UNBLOCK FAILED for ${label} — owner must unblock ${mac} in the UniFi app`);
      process.exit(2);
    }
    console.log('unblock-sta: rc ok');
  }
  const after = await isBlocked(api, mac);
  console.log(`rest/user blocked after unblock-sta: ${String(after ?? false)}`);
  return ok && after !== true;
}

async function main(): Promise<void> {
  const api = createLegacyApi(createUnifiHttpClient(loadConfig(), { timeoutMs: 15_000 }));
  const [devices, stations, networks] = await Promise.all([
    api.devicesBasic(REF),
    api.stations(REF),
    api.networkConf(REF),
  ]);

  const ap = devices.find((d) => d.type === 'uap');
  const target = pickClient(stations, new Map(networks.map((n) => [n._id, n.name])));
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

main().catch((error: unknown) => {
  console.error(`spike failed: ${describeError(error)}`);
  process.exit(1);
});
