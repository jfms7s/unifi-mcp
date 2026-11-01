/**
 * Records every read endpoint the tools use from the live console, scrubs the
 * responses (see scrub.ts) and writes them to test/fixtures/live/.
 *
 *   set -a; . ~/.config/unifi-mcp/.env; set +a
 *   UNIFI_URL=https://192.168.10.1 npx tsx scripts/capture-fixtures.ts
 *
 * `--only firewall` captures just the official firewall objects (zones,
 * policies, the policy ordering of every zone pair, ACL rules, DNS policies,
 * traffic matching lists) and leaves every other fixture as it is, so tests
 * pinned to the earlier capture keep their counts.
 *
 * Reads only: GETs, plus the read-only POSTs to stat/report/* and system-log/*.
 * Never prints a response body or a key; failures print the error kind only.
 */
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig, type UnifiMcpConfig } from '../src/config.js';
import { createUnifiHttpClient, type Api, type UnifiHttpClient } from '../src/http/client.js';
import { describeError } from '../src/http/errors.js';
import { createScrubMap, prime, scrub } from './scrub.js';

export const SITE_REF = 'default';
const OUT_DIR = resolve(import.meta.dirname, '../test/fixtures/live');

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const SYSTEM_LOG_PAGE_SIZE = 1_000;
const SYSTEM_LOG_DAYS = 7;
/**
 * Neighbouring WiFi networks: a few are enough to test with, and every one kept
 * is another MAC in the 255-slot fake range and another neighbour's SSID.
 */
const ROGUE_AP_LIMIT = 25;
/** The only fields of a system-log entry any module reads; the rest is dropped. */
export const SYSTEM_LOG_FIELDS = [
  'id',
  'timestamp',
  'category',
  'subcategory',
  'severity',
  'key',
  'title_raw',
  'message_raw',
  'parameters',
  'type',
  'status',
] as const;

const REPORT_INTERVALS = ['5minutes', 'hourly', 'daily'] as const;
const REPORT_ATTRS: Record<string, string[]> = {
  site: [
    'time',
    'bytes',
    'wan-tx_bytes',
    'wan-rx_bytes',
    'wan2-tx_bytes',
    'wan2-rx_bytes',
    'wlan_bytes',
    'num_sta',
    'lan-num_sta',
    'wlan-num_sta',
  ],
  ap: ['time', 'bytes', 'num_sta', 'tx_bytes', 'rx_bytes'],
  user: ['time', 'rx_bytes', 'tx_bytes'],
  gw: [
    'time',
    'mem',
    'cpu',
    'loadavg_5',
    'lan-rx_bytes',
    'lan-tx_bytes',
    'wan-rx_bytes',
    'wan-tx_bytes',
    'latency_avg',
  ],
};

export interface Captured {
  /** File name without extension: `<api>-<path-slug>`. */
  name: string;
  data: unknown;
  /** Read only so the scrub learns from it (the site list in a partial capture); never written. */
  contextOnly?: boolean;
}

/** What `--only` can narrow a capture to. */
export type Only = 'firewall';

export function parseOnly(argv: string[]): Only | undefined {
  const i = argv.findIndex((a) => a === '--only' || a.startsWith('--only='));
  if (i === -1) return undefined;
  const value = argv[i]!.startsWith('--only=') ? argv[i]!.slice('--only='.length) : argv[i + 1];
  if (value !== 'firewall') throw new Error('--only takes: firewall');
  return value;
}

interface Endpoint {
  name: string;
  api: Api;
  path: string;
  method?: 'GET' | 'POST';
  body?: unknown;
}

const official = (name: string, path: string): Endpoint => ({
  name: `official-${name}`,
  api: 'official',
  path: `/v1${path}`,
});
/**
 * The official-API id of the site whose legacy name is `ref`, read from the
 * console's `/v1/sites` answer: it is the owner's, so it is never hardcoded
 * here (the scrub fakes it in the fixtures).
 */
export function siteIdFor(sites: unknown, ref: string): string {
  const rows = (sites as { data?: Array<{ id?: unknown; internalReference?: unknown }> } | undefined)
    ?.data;
  const id = rows?.find((s) => s.internalReference === ref)?.id;
  if (typeof id !== 'string' || !id) throw new Error(`the console has no site "${ref}"`);
  return id;
}

const sitePath = (siteId: string) => (path: string) => `/sites/${siteId}${path}`;
const legacy = (path: string, method: 'GET' | 'POST' = 'GET', body?: unknown): Endpoint => ({
  name: `legacy-${path.replace(/[/.]/g, '-')}`,
  api: 'legacy',
  path: `/s/${SITE_REF}/${path}`,
  method,
  body,
});

/** The official firewall objects, as `--only firewall` captures them (the ordering comes apart). */
export function firewallEndpoints(siteId: string): Endpoint[] {
  const site = sitePath(siteId);
  return [
    official('firewall-zones', `${site('/firewall/zones')}?limit=200`),
    official('firewall-policies', `${site('/firewall/policies')}?limit=200`),
    official('acl-rules', `${site('/acl-rules')}?limit=200`),
    official('dns-policies', `${site('/dns/policies')}?limit=200`),
    official('traffic-matching-lists', `${site('/traffic-matching-lists')}?limit=200`),
  ];
}

/** Every fixture `--only firewall` writes. */
export const FIREWALL_FIXTURES = [
  ...firewallEndpoints('x').map((e) => e.name),
  'official-firewall-policies-ordering',
];

/** Every (source, destination) zone pair: the console orders policies per pair. */
export function orderingPairs(
  zones: unknown,
): Array<{ sourceZoneId: string; destinationZoneId: string }> {
  const ids = ((zones as { data?: Array<{ id?: unknown }> } | undefined)?.data ?? [])
    .map((z) => z.id)
    .filter((id): id is string => typeof id === 'string');
  if (ids.length === 0) throw new Error('the console answered no zones');
  return ids.flatMap((sourceZoneId) =>
    ids.map((destinationZoneId) => ({ sourceZoneId, destinationZoneId })),
  );
}

function staticEndpoints(now: number, siteId: string): Endpoint[] {
  const site = sitePath(siteId);
  const list: Endpoint[] = [
    official('info', '/info'),
    official('sites', '/sites'),
    official('devices', `${site('/devices')}?limit=200`),
    official('clients', `${site('/clients')}?limit=200`),
    official('networks', `${site('/networks')}?limit=200`),
    official('wifi-broadcasts', `${site('/wifi/broadcasts')}?limit=200`),
    official('wans', `${site('/wans')}?limit=200`),
    official('vpn-servers', `${site('/vpn/servers')}?limit=200`),
    official('vpn-site-to-site-tunnels', `${site('/vpn/site-to-site-tunnels')}?limit=200`),
    official('dpi-applications', '/dpi/applications?limit=200'),
    official('dpi-categories', '/dpi/categories?limit=200'),
    legacy('stat/sysinfo'),
    legacy('stat/health'),
    legacy('stat/sta'),
    legacy('stat/device-basic'),
    legacy('rest/user'),
    legacy('rest/portforward'),
    legacy('rest/wlanconf'),
    legacy('rest/networkconf'),
    legacy('rest/setting'),
    legacy('stat/sitedpi'),
    legacy('stat/rogueap'),
    legacy('rest/firewallrule'),
    { name: 'sitemanager-hosts', api: 'sitemanager', path: '/v1/hosts' },
    { name: 'sitemanager-isp-metrics-1h', api: 'sitemanager', path: '/v1/isp-metrics/1h' },
  ];
  for (const interval of REPORT_INTERVALS) {
    for (const [scope, attrs] of Object.entries(REPORT_ATTRS)) {
      list.push(
        legacy(`stat/report/${interval}.${scope}`, 'POST', { attrs, start: now - DAY, end: now }),
      );
    }
  }
  return list;
}

/** Path and query apart: the client builds the query itself. */
function splitPath(path: string): { path: string; query?: Record<string, string> } {
  const [bare, search] = path.split('?');
  if (!search) return { path: bare! };
  return { path: bare!, query: Object.fromEntries(new URLSearchParams(search)) };
}

async function fetchOne(client: UnifiHttpClient, e: Endpoint): Promise<unknown> {
  const { path, query } = splitPath(e.path);
  return client.request(e.api, e.method ?? 'GET', path, { query, body: e.body });
}

function keepFirst(envelope: unknown, limit: number): unknown {
  const record = envelope as { data?: unknown } | undefined;
  if (!record || !Array.isArray(record.data)) return envelope;
  return { ...record, data: record.data.slice(0, limit) };
}

function pickSystemLogFields(entry: unknown): unknown {
  if (!entry || typeof entry !== 'object') return entry;
  const record = entry as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const field of SYSTEM_LOG_FIELDS) if (field in record) out[field] = record[field];
  return out;
}

async function systemLogPages(client: UnifiHttpClient, now: number): Promise<Captured[]> {
  const pages: Captured[] = [];
  const timestampFrom = now - SYSTEM_LOG_DAYS * DAY;
  for (let pageNumber = 0; ; pageNumber++) {
    const page = await client.request<Record<string, unknown>>(
      'v2',
      'POST',
      `/site/${SITE_REF}/system-log/all`,
      { body: { timestampFrom, timestampTo: now, pageNumber, pageSize: SYSTEM_LOG_PAGE_SIZE } },
    );
    const data = Array.isArray(page?.data) ? page.data : [];
    pages.push({
      name: `v2-system-log-all-page-${pageNumber}`,
      data: { ...page, data: data.map(pickSystemLogFields) },
    });
    // The console answers in snake_case; the camelCase spelling is accepted in case that changes.
    const total = Number(page?.total_element_count ?? page?.totalElementCount ?? 0);
    if (data.length === 0 || (pageNumber + 1) * SYSTEM_LOG_PAGE_SIZE >= total) break;
  }
  return pages;
}

/** The firewall objects and the policy ordering of every zone pair, in one fixture. */
async function collectFirewall(
  client: UnifiHttpClient,
  siteId: string,
  captured: Captured[],
  attempt: (name: string, run: () => Promise<void>) => Promise<void>,
): Promise<void> {
  for (const e of firewallEndpoints(siteId)) {
    await attempt(e.name, async () => {
      captured.push({ name: e.name, data: await fetchOne(client, e) });
    });
  }
  const zones = captured.find((c) => c.name === 'official-firewall-zones')?.data;
  await attempt('official-firewall-policies-ordering', async () => {
    const pairs = [];
    for (const pair of orderingPairs(zones)) {
      const ordering = await client.request(
        'official',
        'GET',
        `/v1${sitePath(siteId)('/firewall/policies/ordering')}`,
        { query: { sourceFirewallZoneId: pair.sourceZoneId, destinationFirewallZoneId: pair.destinationZoneId } },
      );
      pairs.push({ ...pair, ordering });
    }
    // One file for every pair: the tests' fake console answers by the query's zone ids.
    captured.push({ name: 'official-firewall-policies-ordering', data: { pairs } });
  });
}

/** Unscrubbed responses, in a fixed order so the scrub map is deterministic. */
export async function collect(
  config: UnifiMcpConfig,
  only?: Only,
): Promise<{
  captured: Captured[];
  failures: string[];
}> {
  const client = createUnifiHttpClient(config, { timeoutMs: 30_000 });
  const now = Date.now();
  const captured: Captured[] = [];
  const failures: string[] = [];
  const attempt = async (name: string, run: () => Promise<void>) => {
    try {
      await run();
    } catch (error) {
      failures.push(`${name}: ${describeError(error)}`);
    }
  };

  let siteId: string;
  try {
    const sites = await client.request('official', 'GET', '/v1/sites');
    siteId = siteIdFor(sites, SITE_REF);
    // The scrub learns the real site id from it, so it is replaced inside paths too.
    if (only) captured.push({ name: 'official-sites', data: sites, contextOnly: true });
  } catch (error) {
    return { captured, failures: [`official-sites: ${describeError(error)}`] };
  }
  const site = sitePath(siteId);

  if (only === 'firewall') {
    await collectFirewall(client, siteId, captured, attempt);
    return { captured, failures };
  }

  for (const e of staticEndpoints(now, siteId)) {
    await attempt(e.name, async () => {
      captured.push({ name: e.name, data: await fetchOne(client, e) });
    });
  }
  const rogue = captured.find((c) => c.name === 'legacy-stat-rogueap');
  if (rogue) rogue.data = keepFirst(rogue.data, ROGUE_AP_LIMIT);

  const devices = captured.find((c) => c.name === 'official-devices')?.data as
    { data?: Array<{ id?: string }> } | undefined;
  const firstDevice = devices?.data?.[0]?.id;
  if (firstDevice) {
    await attempt('official-devices-statistics-latest', async () => {
      captured.push({
        name: 'official-devices-statistics-latest',
        data: await client.request(
          'official',
          'GET',
          `/v1${site(`/devices/${firstDevice}/statistics/latest`)}`,
        ),
      });
    });
  } else {
    failures.push('official-devices-statistics-latest: no device to ask about');
  }

  await collectFirewall(client, siteId, captured, attempt);

  await attempt('v2-system-log-all', async () => {
    captured.push(...(await systemLogPages(client, now)));
  });

  return { captured, failures };
}

/**
 * Scrubs and writes the fixtures, replacing the folder only when every endpoint
 * was captured: a partial capture leaves the previous fixtures untouched. With
 * `only`, just the captured files are replaced and every other fixture stays.
 */
export async function writeFixtures(
  captured: Captured[],
  failures: string[],
  outDir: string,
  opts: { only?: boolean } = {},
): Promise<void> {
  if (failures.length > 0) {
    throw new Error(
      `capture incomplete, fixtures left as they were:\n${failures.map((f) => `  not captured: ${f}`).join('\n')}`,
    );
  }
  const map = createScrubMap();
  // Learn every name first, so a name first seen in a later file is replaced everywhere.
  for (const { data } of captured) prime(data, map);

  const staging = `${outDir}.staging`;
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  const written: string[] = [];
  for (const { name, data, contextOnly } of captured) {
    if (contextOnly) continue;
    await writeFile(
      join(staging, `${name}.json`),
      `${JSON.stringify(scrub(data, map), null, 2)}\n`,
    );
    written.push(`${name}.json`);
  }
  if (opts.only) {
    for (const file of written) await rename(join(staging, file), join(outDir, file));
    await rm(staging, { recursive: true, force: true });
    return;
  }
  await rm(outDir, { recursive: true, force: true });
  await rename(staging, outDir);
}

async function main(): Promise<void> {
  const only = parseOnly(process.argv.slice(2));
  const { captured, failures } = await collect(loadConfig(), only);
  await writeFixtures(captured, failures, OUT_DIR, { only: only !== undefined });
  const count = captured.filter((c) => !c.contextOnly).length;
  console.log(`wrote ${count} fixtures to ${OUT_DIR}${only ? ` (only ${only})` : ''}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    console.error(describeError(error));
    process.exitCode = 1;
  });
}
