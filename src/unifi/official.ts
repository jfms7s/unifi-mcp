import type { z } from 'zod';
import { UnifiApiError } from '../http/errors.js';
import type { QueryParams, UnifiHttpClient } from '../http/client.js';
import {
  aclRuleSchema,
  anyObjectSchema,
  createdSchema,
  deviceStatsSchema,
  dnsPolicySchema,
  dpiNameSchema,
  firewallPolicySchema,
  firewallZoneSchema,
  fullObjectSchema,
  namedObjectSchema,
  officialClientSchema,
  officialDeviceSchema,
  officialNetworkSchema,
  officialPage,
  policyOrderingSchema,
  trafficListSchema,
  wanSchema,
  wifiBroadcastSchema,
  type AclRule,
  type AnyObject,
  type DeviceStats,
  type DnsPolicy,
  type DpiName,
  type FirewallPolicy,
  type FirewallZone,
  type FullObject,
  type NamedObject,
  type OfficialClient,
  type OfficialDevice,
  type OfficialNetwork,
  type PolicyOrdering,
  type TrafficList,
  type Voucher,
  type Wan,
  type WifiBroadcast,
  voucherCreationSchema,
  voucherDeletionSchema,
  voucherSchema,
} from './schemas.js';

export type {
  AclRule,
  AnyObject,
  DeviceStats,
  DnsPolicy,
  DpiName,
  FirewallPolicy,
  FirewallZone,
  FullObject,
  NamedObject,
  OfficialClient,
  OfficialDevice,
  OfficialNetwork,
  PolicyOrdering,
  TrafficList,
  Voucher,
  Wan,
  WifiBroadcast,
};

/** The firewall objects the official API creates, updates and deletes by id. */
export type FirewallObjectKind = 'policy' | 'zone' | 'acl' | 'dns' | 'traffic-list';

const FIREWALL_PATHS: Record<FirewallObjectKind, string> = {
  policy: '/firewall/policies',
  zone: '/firewall/zones',
  acl: '/acl-rules',
  dns: '/dns/policies',
  'traffic-list': '/traffic-matching-lists',
};

/** A zone pair's user-defined policies, by id, around the system-defined ones. */
export interface PolicyOrder {
  beforeSystemDefined: string[];
  afterSystemDefined: string[];
}

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
  listAcl(siteId: string): Promise<AclRule[]>;
  listDnsPolicies(siteId: string): Promise<DnsPolicy[]>;
  listTrafficLists(siteId: string): Promise<TrafficList[]>;
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

  /** The whole network, every field kept, for a GET-merge-PUT update. */
  getNetwork(siteId: string, networkId: string): Promise<FullObject>;
  /** Resolves to the console's answer (the new network), unparsed. */
  createNetwork(siteId: string, body: object): Promise<unknown>;
  /** The official PUT replaces the network: send the whole object. */
  updateNetwork(siteId: string, networkId: string, body: object): Promise<void>;
  deleteNetwork(siteId: string, networkId: string): Promise<void>;
  /** The whole broadcast, passphrase included: never return it as is. */
  getWifi(siteId: string, wifiId: string): Promise<FullObject>;
  createWifi(siteId: string, body: object): Promise<unknown>;
  /** The official PUT replaces the broadcast: send the whole object. */
  updateWifi(siteId: string, wifiId: string, body: object): Promise<void>;
  deleteWifi(siteId: string, wifiId: string): Promise<void>;
  /** A firewall object whole, every field kept, for a GET-merge-PUT update. */
  getFirewallObject(siteId: string, kind: FirewallObjectKind, id: string): Promise<AnyObject>;
  /** Resolves to the new object's id; an answer without one is endpoint-changed. */
  createFirewallObject(siteId: string, kind: FirewallObjectKind, body: object): Promise<string>;
  /** The official PUT replaces the object: send the whole thing. */
  updateFirewallObject(
    siteId: string,
    kind: FirewallObjectKind,
    id: string,
    body: object,
  ): Promise<void>;
  deleteFirewallObject(siteId: string, kind: FirewallObjectKind, id: string): Promise<void>;
  /** Replaces a zone pair's user-defined order: every user-defined policy, exactly once. */
  reorderFirewallPolicies(
    siteId: string,
    zones: { sourceZoneId: string; destinationZoneId: string },
    order: PolicyOrder,
  ): Promise<void>;
  /** `filter` uses the official filter syntax, e.g. `expired.eq(true)`. */
  listVouchers(siteId: string, filter?: string): Promise<Voucher[]>;
  createVouchers(siteId: string, body: VoucherRequest): Promise<Voucher[]>;
  deleteVoucher(siteId: string, voucherId: string): Promise<number | undefined>;
  /** Deletes every voucher `filter` matches; the console requires a filter. */
  deleteVouchers(siteId: string, filter: string): Promise<number | undefined>;
}

/** `Hotspot voucher creation request` in the Network API spec. */
export interface VoucherRequest {
  name: string;
  timeLimitMinutes: number;
  count?: number;
  authorizedGuestLimit?: number;
  dataUsageLimitMBytes?: number;
  rxRateLimitKbps?: number;
  txRateLimitKbps?: number;
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
  async function list<T extends z.ZodType>(
    path: string,
    item: T,
    filter?: string,
  ): Promise<z.infer<T>[]> {
    const schema = officialPage(item);
    const all: z.infer<T>[] = [];
    for (;;) {
      const query = { offset: all.length, limit: PAGE_SIZE, ...(filter ? { filter } : {}) };
      const page = await get(path, schema, query);
      all.push(...page.data);
      if (page.data.length === 0 || all.length >= page.totalCount) return all;
    }
  }

  const site = (siteId: string, rest: string) => `/v1/sites/${encodeURIComponent(siteId)}${rest}`;
  const device = (siteId: string, deviceId: string, rest = '') =>
    site(siteId, `/devices/${encodeURIComponent(deviceId)}${rest}`);

  async function send(
    method: 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown,
    query?: QueryParams,
  ): Promise<unknown> {
    return client.request('official', method, path, {
      ...(body === undefined ? {} : { body }),
      ...(query === undefined ? {} : { query }),
    });
  }

  /** A write whose answer unifi-mcp reads: a missing used field is endpoint-changed. */
  async function sendParsed<T>(
    method: 'POST' | 'PUT' | 'DELETE',
    path: string,
    schema: z.ZodType<T>,
    opts: { body?: unknown; query?: QueryParams } = {},
  ): Promise<T> {
    const raw = await send(method, path, opts.body, opts.query);
    const parsed = schema.safeParse(raw ?? {});
    if (!parsed.success) {
      throw new UnifiApiError({
        kind: 'endpoint-changed',
        method,
        path,
        detail: 'the response no longer has the fields unifi-mcp reads',
      });
    }
    return parsed.data;
  }

  const network = (s: string, n: string) => site(s, `/networks/${encodeURIComponent(n)}`);
  const wifi = (s: string, w: string) => site(s, `/wifi/broadcasts/${encodeURIComponent(w)}`);
  const vouchers = (s: string) => site(s, '/hotspot/vouchers');
  const firewallObject = (s: string, kind: FirewallObjectKind, id: string) =>
    site(s, `${FIREWALL_PATHS[kind]}/${encodeURIComponent(id)}`);

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
    listAcl: (s) => list(site(s, '/acl-rules'), aclRuleSchema),
    listDnsPolicies: (s) => list(site(s, '/dns/policies'), dnsPolicySchema),
    listTrafficLists: (s) => list(site(s, '/traffic-matching-lists'), trafficListSchema),
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

    getNetwork: (s, n) => get(network(s, n), fullObjectSchema),
    createNetwork: (s, body) => send('POST', site(s, '/networks'), body),
    async updateNetwork(s, n, body) {
      await send('PUT', network(s, n), body);
    },
    async deleteNetwork(s, n) {
      await send('DELETE', network(s, n));
    },
    getWifi: (s, w) => get(wifi(s, w), fullObjectSchema),
    createWifi: (s, body) => send('POST', site(s, '/wifi/broadcasts'), body),
    async updateWifi(s, w, body) {
      await send('PUT', wifi(s, w), body);
    },
    async deleteWifi(s, w) {
      await send('DELETE', wifi(s, w));
    },
    getFirewallObject: (s, kind, id) => get(firewallObject(s, kind, id), anyObjectSchema),
    async createFirewallObject(s, kind, body) {
      return (await sendParsed('POST', site(s, FIREWALL_PATHS[kind]), createdSchema, { body })).id;
    },
    async updateFirewallObject(s, kind, id, body) {
      await send('PUT', firewallObject(s, kind, id), body);
    },
    async deleteFirewallObject(s, kind, id) {
      await send('DELETE', firewallObject(s, kind, id));
    },
    async reorderFirewallPolicies(s, zones, order) {
      await send(
        'PUT',
        site(s, '/firewall/policies/ordering'),
        { orderedFirewallPolicyIds: order },
        {
          sourceFirewallZoneId: zones.sourceZoneId,
          destinationFirewallZoneId: zones.destinationZoneId,
        },
      );
    },
    listVouchers: (s, filter) => list(vouchers(s), voucherSchema, filter),
    async createVouchers(s, body) {
      return (await sendParsed('POST', vouchers(s), voucherCreationSchema, { body })).vouchers;
    },
    async deleteVoucher(s, v) {
      const path = `${vouchers(s)}/${encodeURIComponent(v)}`;
      return (await sendParsed('DELETE', path, voucherDeletionSchema)).vouchersDeleted;
    },
    async deleteVouchers(s, filter) {
      return (await sendParsed('DELETE', vouchers(s), voucherDeletionSchema, { query: { filter } }))
        .vouchersDeleted;
    },
  };
}
