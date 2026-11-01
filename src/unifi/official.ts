import type { z } from 'zod';
import { UnifiApiError } from '../http/errors.js';
import type { QueryParams, UnifiHttpClient } from '../http/client.js';
import {
  deviceStatsSchema,
  dpiNameSchema,
  firewallPolicySchema,
  firewallZoneSchema,
  namedObjectSchema,
  officialClientSchema,
  officialDeviceSchema,
  officialNetworkSchema,
  officialPage,
  policyOrderingSchema,
  wanSchema,
  wifiBroadcastSchema,
  type DeviceStats,
  type DpiName,
  type FirewallPolicy,
  type FirewallZone,
  type NamedObject,
  type OfficialClient,
  type OfficialDevice,
  type OfficialNetwork,
  type PolicyOrdering,
  type Wan,
  type WifiBroadcast,
} from './schemas.js';

export type {
  DeviceStats,
  DpiName,
  FirewallPolicy,
  FirewallZone,
  NamedObject,
  OfficialClient,
  OfficialDevice,
  OfficialNetwork,
  PolicyOrdering,
  Wan,
  WifiBroadcast,
};

export interface OfficialApi {
  listDevices(siteId: string): Promise<OfficialDevice[]>;
  deviceStats(siteId: string, deviceId: string): Promise<DeviceStats>;
  listClients(siteId: string): Promise<OfficialClient[]>;
  listNetworks(siteId: string): Promise<OfficialNetwork[]>;
  listWifi(siteId: string): Promise<WifiBroadcast[]>;
  listWans(siteId: string): Promise<Wan[]>;
  listVpnServers(siteId: string): Promise<NamedObject[]>;
  listS2sTunnels(siteId: string): Promise<NamedObject[]>;
  listDpiApps(): Promise<DpiName[]>;
  listDpiCategories(): Promise<DpiName[]>;
  listAcl(siteId: string): Promise<NamedObject[]>;
  listDnsPolicies(siteId: string): Promise<NamedObject[]>;
  listTrafficLists(siteId: string): Promise<NamedObject[]>;
  /** Rejects with a `zbf-disabled` error while Zone-Based Firewall is off. */
  listFirewallZones(siteId: string): Promise<FirewallZone[]>;
  /** Rejects with a `zbf-disabled` error while Zone-Based Firewall is off. */
  listFirewallPolicies(siteId: string): Promise<FirewallPolicy[]>;
  /** Ordering is per zone pair; the console needs both zone ids. */
  firewallOrdering(
    siteId: string,
    zones: { sourceZoneId: string; destinationZoneId: string },
  ): Promise<PolicyOrdering>;

  // ---- writes: callers go through guard.ts ----
  /** Guest authorize/unauthorize; resolves to the console's answer, unparsed. */
  clientAction(siteId: string, clientId: string, body: ClientActionBody): Promise<unknown>;
  deviceAction(siteId: string, deviceId: string, action: 'RESTART'): Promise<void>;
  portAction(
    siteId: string,
    deviceId: string,
    portIdx: number,
    action: 'POWER_CYCLE',
  ): Promise<void>;
  adoptDevice(siteId: string, macAddress: string): Promise<void>;
  /** The console resets an online device to factory defaults. */
  unadoptDevice(siteId: string, deviceId: string): Promise<void>;
}

/** `Guest access (un)authorization request` in the Network API spec. */
export type ClientActionBody =
  | {
      action: 'AUTHORIZE_GUEST_ACCESS';
      timeLimitMinutes?: number;
      dataUsageLimitMBytes?: number;
      rxRateLimitKbps?: number;
      txRateLimitKbps?: number;
    }
  | { action: 'UNAUTHORIZE_GUEST_ACCESS' };

const PAGE_SIZE = 200;

export function createOfficialApi(client: UnifiHttpClient): OfficialApi {
  function changed(path: string, detail: string): UnifiApiError {
    return new UnifiApiError({ kind: 'endpoint-changed', method: 'GET', path, detail });
  }

  async function get<T>(path: string, schema: z.ZodType<T>, query?: QueryParams): Promise<T> {
    const raw = await client.request('official', 'GET', path, { query });
    const parsed = schema.safeParse(raw);
    if (!parsed.success)
      throw changed(path, 'the response no longer has the fields unifi-mcp reads');
    return parsed.data;
  }

  /** Follows offset/limit until `totalCount` is reached; an empty page also ends it. */
  async function list<T extends z.ZodType>(path: string, item: T): Promise<z.infer<T>[]> {
    const schema = officialPage(item);
    const all: z.infer<T>[] = [];
    for (;;) {
      const page = await get(path, schema, { offset: all.length, limit: PAGE_SIZE });
      all.push(...page.data);
      if (page.data.length === 0 || all.length >= page.totalCount) return all;
    }
  }

  const site = (siteId: string, rest: string) => `/v1/sites/${encodeURIComponent(siteId)}${rest}`;
  const device = (siteId: string, deviceId: string, rest = '') =>
    site(siteId, `/devices/${encodeURIComponent(deviceId)}${rest}`);

  async function send(method: 'POST' | 'DELETE', path: string, body?: unknown): Promise<unknown> {
    return client.request('official', method, path, body === undefined ? {} : { body });
  }

  return {
    listDevices: (s) => list(site(s, '/devices'), officialDeviceSchema),
    deviceStats: (s, d) =>
      get(site(s, `/devices/${encodeURIComponent(d)}/statistics/latest`), deviceStatsSchema),
    listClients: (s) => list(site(s, '/clients'), officialClientSchema),
    listNetworks: (s) => list(site(s, '/networks'), officialNetworkSchema),
    listWifi: (s) => list(site(s, '/wifi/broadcasts'), wifiBroadcastSchema),
    listWans: (s) => list(site(s, '/wans'), wanSchema),
    listVpnServers: (s) => list(site(s, '/vpn/servers'), namedObjectSchema),
    listS2sTunnels: (s) => list(site(s, '/vpn/site-to-site-tunnels'), namedObjectSchema),
    listDpiApps: () => list('/v1/dpi/applications', dpiNameSchema),
    listDpiCategories: () => list('/v1/dpi/categories', dpiNameSchema),
    listAcl: (s) => list(site(s, '/acl-rules'), namedObjectSchema),
    listDnsPolicies: (s) => list(site(s, '/dns/policies'), namedObjectSchema),
    listTrafficLists: (s) => list(site(s, '/traffic-matching-lists'), namedObjectSchema),
    listFirewallZones: (s) => list(site(s, '/firewall/zones'), firewallZoneSchema),
    listFirewallPolicies: (s) => list(site(s, '/firewall/policies'), firewallPolicySchema),
    firewallOrdering: (s, zones) =>
      get(site(s, '/firewall/policies/ordering'), policyOrderingSchema, {
        sourceFirewallZoneId: zones.sourceZoneId,
        destinationFirewallZoneId: zones.destinationZoneId,
      }),

    clientAction: (s, c, body) =>
      send('POST', site(s, `/clients/${encodeURIComponent(c)}/actions`), body),
    async deviceAction(s, d, action) {
      await send('POST', device(s, d, '/actions'), { action });
    },
    async portAction(s, d, portIdx, action) {
      await send('POST', device(s, d, `/interfaces/ports/${portIdx}/actions`), { action });
    },
    async adoptDevice(s, macAddress) {
      await send('POST', site(s, '/devices'), { macAddress, ignoreDeviceLimit: false });
    },
    async unadoptDevice(s, d) {
      await send('DELETE', device(s, d));
    },
  };
}
