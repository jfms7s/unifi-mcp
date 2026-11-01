import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { loadClients } from './clients.js';
import { parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import type { ReportInterval, ReportScope } from './legacy.js';
import { ambiguous, findClient, findDevice } from './lookup.js';
import { DAY_MS, READ, type ReadDeps } from './read-common.js';
import { MAX_REPORT_POINTS, downsample } from './reports.js';
import type { DpiRow, ReportRow } from './schemas.js';
import { compact, iso } from './shape.js';
import { ispMetricsReader } from './wan-tools.js';

const TOP_N = 10;

const SCOPES = {
  site: {
    legacy: 'site',
    attrs: ['time', 'wan-tx_bytes', 'wan-rx_bytes', 'wan2-tx_bytes', 'wan2-rx_bytes', 'wlan_bytes', 'num_sta', 'lan-num_sta', 'wlan-num_sta'],
  },
  ap: { legacy: 'ap', attrs: ['time', 'bytes', 'num_sta', 'tx_bytes', 'rx_bytes'] },
  client: { legacy: 'user', attrs: ['time', 'rx_bytes', 'tx_bytes'] },
  gateway: {
    legacy: 'gw',
    attrs: ['time', 'mem', 'cpu', 'lan-rx_bytes', 'lan-tx_bytes', 'wan-rx_bytes', 'wan-tx_bytes', 'latency_avg'],
  },
} as const satisfies Record<string, { legacy: ReportScope; attrs: readonly string[] }>;

type Scope = keyof typeof SCOPES;
type Point = { time: number } & Record<string, number>;

function num(row: ReportRow, key: string): number | undefined {
  const v = row[key];
  return typeof v === 'number' ? v : undefined;
}

function sum(row: ReportRow, keys: string[]): number | undefined {
  const values = keys.map((k) => num(row, k)).filter((v): v is number => v !== undefined);
  return values.length === 0 ? undefined : values.reduce((a, b) => a + b, 0);
}

/** One friendly point per row; bytes are what the bucket moved, WAN-side for the site and gateway. */
function toPoint(scope: Scope, row: ReportRow): Point {
  const wan = ['wan-rx_bytes', 'wan-tx_bytes', 'wan2-rx_bytes', 'wan2-tx_bytes'];
  const fields: Record<string, number | undefined> =
    scope === 'site'
      ? {
          bytes: sum(row, wan),
          wlanBytes: num(row, 'wlan_bytes'),
          clients: num(row, 'num_sta'),
          wiredClients: num(row, 'lan-num_sta'),
          wirelessClients: num(row, 'wlan-num_sta'),
        }
      : scope === 'ap'
        ? {
            bytes: num(row, 'bytes') ?? sum(row, ['rx_bytes', 'tx_bytes']),
            rxBytes: num(row, 'rx_bytes'),
            txBytes: num(row, 'tx_bytes'),
            clients: num(row, 'num_sta'),
          }
        : scope === 'client'
          ? {
              bytes: sum(row, ['rx_bytes', 'tx_bytes']),
              rxBytes: num(row, 'rx_bytes'),
              txBytes: num(row, 'tx_bytes'),
            }
          : {
              bytes: sum(row, wan.slice(0, 2)),
              wanRxBytes: num(row, 'wan-rx_bytes'),
              wanTxBytes: num(row, 'wan-tx_bytes'),
              lanRxBytes: num(row, 'lan-rx_bytes'),
              lanTxBytes: num(row, 'lan-tx_bytes'),
              latencyMs: num(row, 'latency_avg'),
              cpuPct: num(row, 'cpu'),
              memoryPct: num(row, 'mem'),
            };
  return { time: row.time, ...compact(fields) } as Point;
}

/** 5-minute buckets are kept about a day; a week reads best hourly, longer by the day. */
function pickInterval(spanMs: number): ReportInterval {
  return spanMs <= 2 * DAY_MS ? '5minutes' : spanMs <= 31 * DAY_MS ? 'hourly' : 'daily';
}

const hex = (id: number) => id & 0xffff;

interface Count {
  rx: number;
  tx: number;
  cat?: number;
}

function addTo(map: Map<number, Count>, id: number, rx: number, tx: number, cat?: number) {
  const have = map.get(id) ?? { rx: 0, tx: 0, cat };
  map.set(id, { rx: have.rx + rx, tx: have.tx + tx, cat: have.cat ?? cat });
}

/** Sums DPI rows by application and by category. An application id carries its category in the high 16 bits. */
function tally(rows: DpiRow[]) {
  const apps = new Map<number, Count>();
  const cats = new Map<number, Count>();
  for (const row of rows) {
    for (const a of row.by_app ?? []) addTo(apps, hex(a.app ?? 0), a.rx_bytes, a.tx_bytes, a.cat);
    for (const c of row.by_cat ?? []) addTo(cats, c.cat, c.rx_bytes, c.tx_bytes);
  }
  return { apps, cats };
}

const topByBytes = (map: Map<number, Count>) =>
  [...map.entries()].sort(([, a], [, b]) => b.rx + b.tx - (a.rx + a.tx)).slice(0, TOP_N);

export function createMetricsTools(deps: ReadDeps): ToolDefinition[] {
  const { official, legacy, sites, sitemanager } = deps;
  const now = deps.now ?? Date.now;

  const tools: ToolDefinition[] = [
    defineTool({
      name: 'unifi_traffic_report',
      description:
        'Traffic and client counts over time from the console\'s own reports, for the whole site, one AP (device), one client, or the gateway (with WAN latency, CPU, memory). Interval 5minutes, hourly or daily (default by range). At most 200 points: longer series are averaged per bucket, first and last kept. Bytes are per bucket of the chosen interval.',
      inputSchema: {
        scope: z.enum(['site', 'ap', 'client', 'gateway']).describe('What to report on; ap needs device, client needs client'),
        device: z.string().min(1).optional().describe('AP name, MAC, IP or id (scope ap)'),
        client: z.string().min(1).optional().describe('Client name, MAC, IP or id (scope client)'),
        interval: z.enum(['5minutes', 'hourly', 'daily']).optional().describe('Bucket size; default 5minutes up to 2 days, hourly up to 31 days, else daily'),
        since: sinceInput,
        until: untilInput,
        site: siteInput,
      },
      annotations: READ,
      handler: async (a) => {
        const scope = a.scope as Scope;
        const interval = a.interval as ReportInterval | undefined;
        const site = await sites.resolve(a.site);
        const range = parseRange(a.since, a.until, '24h', now());

        let target: { name: string; mac: string } | undefined;
        if (scope === 'ap' || scope === 'gateway') {
          if (scope === 'ap' && a.device === undefined) throw new Error('scope ap needs a device');
          if (a.device !== undefined) {
            const match = findDevice(await official.listDevices(site.id), a.device);
            if ('none' in match) throw new Error(`No device matches "${a.device}"`);
            if ('ambiguous' in match) {
              return ambiguous(a.device, match.ambiguous, (d) => ({ id: d.id, name: d.name, model: d.model }));
            }
            target = { name: match.found.name, mac: match.found.macAddress };
          }
        } else if (scope === 'client') {
          if (a.client === undefined) throw new Error('scope client needs a client');
          const match = findClient(await loadClients(deps, site), a.client);
          if ('none' in match) throw new Error(`No client matches "${a.client}"`);
          if ('ambiguous' in match) {
            return ambiguous(a.client, match.ambiguous, (c) => ({ id: c.id, name: c.name, ip: c.ip }));
          }
          target = { name: match.found.name, mac: match.found.mac };
        }

        const chosen = interval ?? pickInterval(range.to - range.from);
        const cfg = SCOPES[scope];
        const rows = await legacy.report(site.ref, chosen, cfg.legacy, { start: range.from, end: range.to }, [...cfg.attrs]);
        const mine = rows
          .filter((r) => r.time >= range.from && r.time <= range.to)
          .filter((r) => target === undefined || String(r.oid ?? '').toLowerCase() === target.mac.toLowerCase())
          .sort((x, y) => x.time - y.time);
        const points = downsample(mine.map((r) => toPoint(scope, r)), MAX_REPORT_POINTS);
        return compact({
          site: site.name,
          scope,
          target: target && { name: target.name },
          interval: chosen,
          range: { from: iso(range.from), to: iso(range.to) },
          downsampled: points.length < mine.length ? { from: mine.length, to: points.length } : undefined,
          points: points.map(({ time, ...rest }) => ({ time: iso(time), ...rest })),
        });
      },
    }),

    defineTool({
      name: 'unifi_top_apps',
      description:
        'Top 10 applications and categories by traffic (deep packet inspection), for the whole site or one client. Ids are named from the official DPI catalogue; an id it lacks shows as "app <id>". Empty when the console has no DPI data.',
      inputSchema: {
        client: z.string().min(1).optional().describe('Client name, MAC, IP or id; omit for the whole site'),
        site: siteInput,
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        let rows: DpiRow[];
        let target: string | undefined;
        if (a.client === undefined) {
          rows = await legacy.siteDpi(site.ref);
        } else {
          const match = findClient(await loadClients(deps, site), a.client);
          if ('none' in match) throw new Error(`No client matches "${a.client}"`);
          if ('ambiguous' in match) {
            return ambiguous(a.client, match.ambiguous, (c) => ({ id: c.id, name: c.name, ip: c.ip }));
          }
          const mac = match.found.mac.toLowerCase();
          target = match.found.name;
          rows = (await legacy.stationDpi(site.ref, [match.found.mac])).filter((r) => r.mac?.toLowerCase() === mac);
        }
        const { apps, cats } = tally(rows);
        const [appNames, catNames] = await Promise.all([official.listDpiApps(), official.listDpiCategories()]);
        const appName = new Map(appNames.map((n) => [n.id, n.name]));
        const catName = new Map(catNames.map((n) => [n.id, n.name]));
        const bytes = (c: Count) => c.rx + c.tx;
        return compact({
          site: site.name,
          scope: target === undefined ? 'site' : 'client',
          client: target,
          apps: topByBytes(apps).map(([id, c]) =>
            compact({
              name: appName.get(id) ?? `app ${id}`,
              category: c.cat === undefined ? undefined : (catName.get(c.cat) ?? `category ${c.cat}`),
              bytes: bytes(c),
              rxBytes: c.rx,
              txBytes: c.tx,
            }),
          ),
          categories: topByBytes(cats).map(([id, c]) => ({
            name: catName.get(id) ?? `category ${id}`,
            bytes: bytes(c),
            rxBytes: c.rx,
            txBytes: c.tx,
          })),
          note: rows.every((r) => !r.by_app?.length && !r.by_cat?.length)
            ? 'The console returned no DPI data (DPI may be off, or nothing has been classified yet)'
            : undefined,
        });
      },
    }),
  ];

  if (sitemanager) {
    const ispMetrics = ispMetricsReader(deps);
    tools.push(
      defineTool({
        name: 'unifi_isp_metrics',
        description:
          'ISP latency, packet loss, uptime and downtime over a range (default 24 h) from Site Manager: 5-minute data up to a day, hourly beyond. Only available with a Site Manager key.',
        inputSchema: { since: sinceInput, until: untilInput },
        annotations: READ,
        handler: async ({ since, until }) => ispMetrics(parseRange(since, until, '24h', now())),
      }),
    );
  }
  return tools;
}
