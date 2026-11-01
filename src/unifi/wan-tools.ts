import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { describeError } from '../http/errors.js';
import { parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import { DAY_MS, READ, type ReadDeps } from './read-common.js';
import { compact, iso } from './shape.js';

/** ISP latency, loss and uptime over a range from Site Manager; says why when it cannot. */
export function ispMetricsReader({ sitemanager }: ReadDeps) {
  return async (range: { from: number; to: number }) => {
    if (!sitemanager) {
      return { available: false, reason: 'UNIFI_SITE_MANAGER_API_KEY is not set' };
    }
    const interval = range.to - range.from <= DAY_MS ? '5m' : '1h';
    try {
      const rows = await sitemanager.ispMetrics(interval, {
        begin: new Date(range.from).toISOString(),
        end: new Date(range.to).toISOString(),
      });
      return {
        interval,
        range: { from: iso(range.from), to: iso(range.to) },
        series: rows.map((r) => summariseIsp(r.hostId, r.siteId, r.periods.map((p) => p.data.wan))),
      };
    } catch (error) {
      return { available: false, reason: describeError(error) };
    }
  };
}

export function createWanTools(deps: ReadDeps): ToolDefinition[] {
  const { official, legacy, sites } = deps;
  const now = deps.now ?? Date.now;

  const ispMetrics = ispMetricsReader(deps);

  return [
    defineTool({
      name: 'unifi_wan_status',
      description:
        'WAN state: the configured WANs, the gateway\'s WAN IP, ISP and link status, internet latency and drops now, and (with a Site Manager key) ISP latency, loss and uptime over a range (default 24 h).',
      inputSchema: { site: siteInput, since: sinceInput, until: untilInput },
      annotations: READ,
      handler: async ({ site: wanted, since, until }) => {
        const site = await sites.resolve(wanted);
        const range = parseRange(since, until, '24h', now());
        const [wans, health] = await Promise.all([official.listWans(site.id), legacy.health(site.ref)]);
        const wan = health.find((h) => h.subsystem === 'wan');
        const www = health.find((h) => h.subsystem === 'www');
        return compact({
          site: site.name,
          wans: wans.map((w) => ({ id: w.id, name: w.name })),
          // The health data names its links WAN, WAN2; it does not say which is active.
          perWan: Object.entries(wan?.uptime_stats ?? {}).map(([name, u]) =>
            compact({ name, availabilityPct: u.availability, latencyMs: u.latency_average }),
          ),
          gateway: wan && compact({ status: wan.status, wanIp: wan.wan_ip, isp: wan.isp_name }),
          internet:
            www &&
            compact({
              status: www.status,
              latencyMs: www.latency,
              drops: www.drops,
              uptimeSec: www.uptime,
              speedtestUpMbps: www.xput_up,
              speedtestDownMbps: www.xput_down,
            }),
          ispMetrics: await ispMetrics(range),
        });
      },
    }),

    defineTool({
      name: 'unifi_vpn_status',
      description: 'VPN servers and site-to-site tunnels with their state, plus the console\'s VPN health.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [servers, tunnels, health] = await Promise.all([
          official.listVpnServers(site.id),
          official.listS2sTunnels(site.id),
          legacy.health(site.ref),
        ]);
        const row = (o: { id: string; name?: string; enabled?: boolean; type?: string }) =>
          compact({ id: o.id, name: o.name, enabled: o.enabled, type: o.type });
        return {
          site: site.name,
          health: health.find((h) => h.subsystem === 'vpn')?.status ?? 'unknown',
          servers: servers.map(row),
          siteToSiteTunnels: tunnels.map(row),
        };
      },
    }),
  ];

}

interface WanPeriod {
  avgLatency?: number;
  maxLatency?: number;
  packetLoss?: number;
  uptime?: number;
  downtime?: number;
}

function summariseIsp(hostId: string, siteId: string, periods: WanPeriod[]) {
  const mean = (pick: (p: WanPeriod) => number | undefined) => {
    const values = periods.map(pick).filter((v): v is number => v !== undefined);
    return values.length === 0 ? undefined : values.reduce((a, b) => a + b, 0) / values.length;
  };
  const round = (v: number | undefined) => (v === undefined ? undefined : Math.round(v * 100) / 100);
  const maxes = periods.map((p) => p.maxLatency).filter((v): v is number => v !== undefined);
  return compact({
    hostId,
    siteId,
    periods: periods.length,
    avgLatencyMs: round(mean((p) => p.avgLatency)),
    maxLatencyMs: maxes.length === 0 ? undefined : Math.max(...maxes),
    avgPacketLossPct: round(mean((p) => p.packetLoss)),
    uptimePct: round(mean((p) => p.uptime)),
    periodsWithDowntime: periods.filter((p) => (p.downtime ?? 0) > 0).length,
  });
}

export function createHostTools({ sitemanager }: ReadDeps): ToolDefinition[] {
  if (!sitemanager) return [];
  return [
    defineTool({
      name: 'unifi_list_hosts',
      description: 'List the consoles on the Site Manager account with their name, state and version.',
      inputSchema: {},
      annotations: READ,
      handler: async () => {
        const hosts = await sitemanager.hosts();
        return {
          hosts: hosts.map((h) =>
            compact({
              id: h.id,
              name: h.reportedState?.name,
              type: h.type,
              state: h.reportedState?.state,
              version: h.reportedState?.version,
              ip: h.ipAddress,
              blocked: h.isBlocked,
              lastStateChange: h.lastConnectionStateChange,
            }),
          ),
        };
      },
    }),
  ];
}
