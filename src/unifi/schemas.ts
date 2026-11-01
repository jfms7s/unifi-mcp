import { z } from 'zod';

/*
 * Only the fields a tool reads. Unknown fields are dropped (zod's default), and a
 * missing or mistyped used field fails the parse, which the callers report as
 * "endpoint changed". Fields the console omits for some rows are optional.
 */

// ---- legacy envelope -------------------------------------------------------

export function legacyEnvelope<T extends z.ZodType>(row: T) {
  return z.object({
    meta: z.object({ rc: z.literal('ok') }),
    data: z.array(row),
  });
}

export const sysInfoSchema = z.object({
  version: z.string(),
  name: z.string().optional(),
  hostname: z.string().optional(),
  build: z.string().optional(),
  timezone: z.string().optional(),
  update_available: z.boolean().optional(),
  ip_addrs: z.array(z.string()).optional(),
});
export type SysInfo = z.infer<typeof sysInfoSchema>;

export const healthSchema = z.object({
  subsystem: z.string(),
  status: z.string(),
  num_user: z.number().optional(),
  num_guest: z.number().optional(),
  num_iot: z.number().optional(),
  num_ap: z.number().optional(),
  num_sw: z.number().optional(),
  num_gw: z.number().optional(),
  num_adopted: z.number().optional(),
  num_disconnected: z.number().optional(),
  num_pending: z.number().optional(),
  'tx_bytes-r': z.number().optional(),
  'rx_bytes-r': z.number().optional(),
  wan_ip: z.string().optional(),
  isp_name: z.string().optional(),
  latency: z.number().optional(),
  uptime: z.number().optional(),
  drops: z.number().optional(),
  xput_up: z.number().optional(),
  xput_down: z.number().optional(),
  gw_version: z.string().optional(),
  /** Per WAN (`WAN`, `WAN2`): link availability and latency over the last period. */
  uptime_stats: z
    .record(
      z.string(),
      z.object({
        availability: z.number().optional(),
        latency_average: z.number().optional(),
      }),
    )
    .optional(),
});
export type Health = z.infer<typeof healthSchema>;

export const stationSchema = z.object({
  mac: z.string(),
  is_wired: z.boolean(),
  _id: z.string().optional(),
  ip: z.string().optional(),
  last_ip: z.string().optional(),
  hostname: z.string().optional(),
  name: z.string().optional(),
  oui: z.string().optional(),
  network: z.string().optional(),
  network_id: z.string().optional(),
  is_guest: z.boolean().optional(),
  blocked: z.boolean().optional(),
  first_seen: z.number().optional(),
  last_seen: z.number().optional(),
  uptime: z.number().optional(),
  tx_bytes: z.number().optional(),
  rx_bytes: z.number().optional(),
  // wireless only
  essid: z.string().optional(),
  ap_mac: z.string().optional(),
  signal: z.number().optional(),
  rssi: z.number().optional(),
  tx_rate: z.number().optional(),
  rx_rate: z.number().optional(),
  satisfaction: z.number().optional(),
  radio: z.string().optional(),
  channel: z.number().optional(),
  // wired only
  sw_mac: z.string().optional(),
  sw_port: z.number().optional(),
  last_uplink_name: z.string().optional(),
});
export type Station = z.infer<typeof stationSchema>;

export const deviceBasicSchema = z.object({
  mac: z.string(),
  type: z.string(),
  model: z.string(),
  state: z.number(),
  adopted: z.boolean(),
  disabled: z.boolean(),
  name: z.string().optional(),
});
export type DeviceBasic = z.infer<typeof deviceBasicSchema>;

const uplinkSchema = z.object({
  uplink_mac: z.string().optional(),
  uplink_remote_port: z.number().optional(),
});

const devicePortSchema = z.object({
  port_idx: z.number(),
  up: z.boolean(),
  /** The port can deliver PoE. */
  port_poe: z.boolean().optional(),
  poe_good: z.boolean().optional(),
  /** Watts, as a string ("3.55"). */
  poe_power: z.union([z.string(), z.number()]).optional(),
});

const radioStatsSchema = z.object({
  /** `ng` 2.4 GHz, `na` 5 GHz, `6e` 6 GHz. */
  radio: z.string(),
  channel: z.union([z.number(), z.string()]).optional(),
  num_sta: z.number().optional(),
});

/**
 * stat/device: where each device hangs (R15), and its ports and radios for the
 * device list. An offline device keeps only `last_uplink`; a gateway's uplink
 * is the WAN and names no parent.
 */
export const deviceSchema = z.object({
  mac: z.string(),
  name: z.string().optional(),
  type: z.string().optional(),
  uplink: uplinkSchema.optional(),
  last_uplink: uplinkSchema.optional(),
  port_table: z.array(devicePortSchema).optional(),
  radio_table_stats: z.array(radioStatsSchema).optional(),
});
export type Device = z.infer<typeof deviceSchema>;

/** rest/user: every client the console has ever seen. */
export const userSchema = z.object({
  _id: z.string(),
  mac: z.string(),
  name: z.string().optional(),
  hostname: z.string().optional(),
  last_ip: z.string().optional(),
  fixed_ip: z.string().optional(),
  blocked: z.boolean().optional(),
  is_wired: z.boolean().optional(),
  first_seen: z.number().optional(),
  last_seen: z.number().optional(),
  last_connection_network_id: z.string().optional(),
  /** Where the client was last seen: the switch or AP, and the switch port (wired). */
  last_uplink_mac: z.string().optional(),
  last_uplink_remote_port: z.number().optional(),
});
export type User = z.infer<typeof userSchema>;

export const portForwardSchema = z.object({
  _id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  fwd: z.string(),
  dst_port: z.string(),
  fwd_port: z.string().optional(),
  proto: z.string(),
  src: z.string().optional(),
});

export const wlanConfSchema = z.object({
  _id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  security: z.string(),
  wpa_mode: z.string().optional(),
  wpa3_support: z.boolean().optional(),
  wpa3_transition: z.boolean().optional(),
  pmf_mode: z.string().optional(),
  hide_ssid: z.boolean().optional(),
  is_guest: z.boolean().optional(),
  l2_isolation: z.boolean().optional(),
  networkconf_id: z.string().optional(),
  wlan_bands: z.array(z.string()).optional(),
});
export type WlanConf = z.infer<typeof wlanConfSchema>;

export const networkConfSchema = z.object({
  _id: z.string(),
  name: z.string(),
  purpose: z.string(),
  enabled: z.boolean().optional(),
  vlan_enabled: z.boolean().optional(),
  vlan: z.number().optional(),
  ip_subnet: z.string().optional(),
  networkgroup: z.string().optional(),
  dhcpd_enabled: z.boolean().optional(),
  is_nat: z.boolean().optional(),
  network_isolation_enabled: z.boolean().optional(),
  internet_access_enabled: z.boolean().optional(),
  wan_ip: z.string().optional(),
});
export type NetworkConf = z.infer<typeof networkConfSchema>;

/** rest/setting holds one row per section, told apart by `key`; each reads only its own fields. */
export const settingSchema = z.object({
  key: z.string(),
  ips_mode: z.string().optional(),
  enabled: z.boolean().optional(),
  upnp_enabled: z.boolean().optional(),
  name: z.string().optional(),
});
export type Setting = z.infer<typeof settingSchema>;

/** rest/firewallrule: the pre-zone firewall, read-only while Zone-Based Firewall is off. */
export const firewallRuleSchema = z.object({
  _id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  ruleset: z.string(),
  rule_index: z.number(),
  action: z.string(),
  protocol: z.string().optional(),
  src_address: z.string().optional(),
  src_networkconf_id: z.string().optional(),
  src_firewallgroup_ids: z.array(z.string()).optional(),
  dst_address: z.string().optional(),
  dst_networkconf_id: z.string().optional(),
  dst_firewallgroup_ids: z.array(z.string()).optional(),
  dst_port: z.string().optional(),
});
export type FirewallRule = z.infer<typeof firewallRuleSchema>;

const dpiCountSchema = z.object({
  app: z.number().optional(),
  cat: z.number(),
  rx_bytes: z.number(),
  tx_bytes: z.number(),
});
export const dpiSchema = z.object({
  mac: z.string().optional(),
  by_app: z.array(dpiCountSchema).optional(),
  by_cat: z.array(dpiCountSchema).optional(),
});
export type DpiRow = z.infer<typeof dpiSchema>;

export const rogueApSchema = z.object({
  bssid: z.string(),
  channel: z.number(),
  essid: z.string().optional(),
  ap_mac: z.string().optional(),
  signal: z.number().optional(),
  rssi: z.number().optional(),
  security: z.string().optional(),
  band: z.string().optional(),
  oui: z.string().optional(),
  is_rogue: z.boolean().optional(),
  is_ubnt: z.boolean().optional(),
  last_seen: z.number().optional(),
});
export type RogueAp = z.infer<typeof rogueApSchema>;

/** The attributes of a report row are whatever was asked for, so only `time` is fixed. */
export const reportRowSchema = z
  .object({ time: z.number() })
  .catchall(z.union([z.number(), z.string()]));
export type ReportRow = z.infer<typeof reportRowSchema>;

// ---- v2 system log ---------------------------------------------------------

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH'] as const;

const parameterSchema = z.object({ id: z.string().optional(), name: z.string().optional() });

export const syslogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.number(),
  category: z.string(),
  severity: z.enum(SEVERITIES),
  key: z.string(),
  title_raw: z.string(),
  message_raw: z.string(),
  parameters: z.record(z.string(), parameterSchema),
});

export const syslogPageSchema = z.object({
  total_element_count: z.number(),
  data: z.array(syslogEntrySchema),
});

// ---- official --------------------------------------------------------------

export function officialPage<T extends z.ZodType>(item: T) {
  return z.object({
    offset: z.number(),
    limit: z.number(),
    count: z.number(),
    totalCount: z.number(),
    data: z.array(item),
  });
}

export const siteSchema = z.object({
  id: z.string(),
  internalReference: z.string(),
  name: z.string(),
});

export const officialDeviceSchema = z.object({
  id: z.string(),
  macAddress: z.string(),
  name: z.string(),
  model: z.string(),
  state: z.string(),
  ipAddress: z.string().optional(),
  firmwareVersion: z.string().optional(),
  firmwareUpdatable: z.boolean().optional(),
  features: z.array(z.string()).optional(),
  interfaces: z.array(z.string()).optional(),
});
export type OfficialDevice = z.infer<typeof officialDeviceSchema>;

export const deviceStatsSchema = z.object({
  uptimeSec: z.number().optional(),
  lastHeartbeatAt: z.string().optional(),
  cpuUtilizationPct: z.number().optional(),
  memoryUtilizationPct: z.number().optional(),
  uplink: z
    .object({ txRateBps: z.number().optional(), rxRateBps: z.number().optional() })
    .optional(),
});
export type DeviceStats = z.infer<typeof deviceStatsSchema>;

export const officialClientSchema = z.object({
  id: z.string(),
  type: z.string(),
  name: z.string(),
  ipAddress: z.string().optional(),
  macAddress: z.string().optional(),
  connectedAt: z.string().optional(),
  uplinkDeviceId: z.string().optional(),
  access: z.object({ type: z.string() }).optional(),
});
export type OfficialClient = z.infer<typeof officialClientSchema>;

export const officialNetworkSchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  vlanId: z.number(),
  management: z.string(),
  default: z.boolean().optional(),
});
export type OfficialNetwork = z.infer<typeof officialNetworkSchema>;

export const wifiBroadcastSchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  type: z.string(),
  securityConfiguration: z.object({ type: z.string() }),
  network: z.object({ type: z.string(), networkId: z.string().optional() }).optional(),
  broadcastingFrequenciesGHz: z.array(z.number()).optional(),
});
export type WifiBroadcast = z.infer<typeof wifiBroadcastSchema>;

export const wanSchema = z.object({ id: z.string(), name: z.string() });
export type Wan = z.infer<typeof wanSchema>;

/** VPN servers, tunnels and the firewall objects were empty on the console this was written against. */
export const namedObjectSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  enabled: z.boolean().optional(),
  type: z.string().optional(),
});
export type NamedObject = z.infer<typeof namedObjectSchema>;

/** Whether UniFi or a user made an object: `SYSTEM_DEFINED` ones are UniFi's to manage. */
const originSchema = z.object({ origin: z.string() });

/** An address match: `IP_ADDRESS` / `SUBNET` (`value`) or `IP_ADDRESS_RANGE` (`start`, `stop`). */
const ipMatchSchema = z.object({
  type: z.string(),
  value: z.string().optional(),
  start: z.string().optional(),
  stop: z.string().optional(),
});
/** A port match: `PORT_NUMBER` (`value`) or `PORT_NUMBER_RANGE` (`start`, `stop`). */
const portMatchSchema = z.object({
  type: z.string(),
  value: z.number().optional(),
  start: z.number().optional(),
  stop: z.number().optional(),
});

/**
 * What narrows one side of a zone policy (absent means the whole zone). The
 * filter kinds unifi-mcp places (`NETWORK`, `IP_ADDRESS`) are typed; the rest
 * (`PORT`, `MAC_ADDRESS`, `REGION`, `DOMAIN`, ...) are only named in output.
 */
export const policyFilterSchema = z.object({
  type: z.string(),
  networkFilter: z
    .object({ networkIds: z.array(z.string()), matchOpposite: z.boolean().optional() })
    .nullish(),
  ipAddressFilter: z
    .object({
      /** `IP_ADDRESSES` (items) or `TRAFFIC_MATCHING_LIST` (trafficMatchingListId). */
      type: z.string(),
      matchOpposite: z.boolean().optional(),
      items: z.array(ipMatchSchema).optional(),
      trafficMatchingListId: z.string().optional(),
    })
    .nullish(),
  portFilter: z
    .object({
      type: z.string(),
      matchOpposite: z.boolean().optional(),
      items: z.array(portMatchSchema).optional(),
      trafficMatchingListId: z.string().optional(),
    })
    .nullish(),
});
export type PolicyFilter = z.infer<typeof policyFilterSchema>;

const policySideSchema = z.object({
  zoneId: z.string(),
  /** The console may send null for "no filter". */
  trafficFilter: policyFilterSchema.nullish(),
});

export const firewallPolicySchema = z.object({
  /** The console sends IPS auto-blocks without one, so the API can't address them. */
  id: z.string().optional(),
  name: z.string(),
  enabled: z.boolean(),
  index: z.number().optional(),
  action: z.object({ type: z.string(), allowReturnTraffic: z.boolean().optional() }),
  /** Read so that only truly identical policies are grouped as copies. */
  description: z.string().nullish(),
  loggingEnabled: z.boolean().optional(),
  ipsecFilter: z.string().nullish(),
  schedule: z.unknown().optional(),
  source: policySideSchema,
  destination: policySideSchema,
  /** Set on policies that only match some connection states (e.g. return traffic). */
  connectionStateFilter: z.array(z.string()).optional(),
  ipProtocolScope: z.object({
    ipVersion: z.string(),
    protocolFilter: z
      .object({
        type: z.string(),
        matchOpposite: z.boolean().optional(),
        protocol: z.object({ name: z.string() }).optional(),
        preset: z.object({ name: z.string() }).optional(),
        protocolNumber: z.number().optional(),
      })
      .optional(),
  }),
  metadata: originSchema,
});
export type FirewallPolicy = z.infer<typeof firewallPolicySchema>;

export const firewallZoneSchema = z.object({
  id: z.string(),
  name: z.string(),
  networkIds: z.array(z.string()),
  metadata: originSchema,
});
export type FirewallZone = z.infer<typeof firewallZoneSchema>;

/** One endpoint of an ACL rule: `NETWORKS`, `IP_ADDRESSES_OR_SUBNETS`, `PORTS`, or a MAC endpoint. */
export const aclEndpointSchema = z.object({
  type: z.string(),
  networkIds: z.array(z.string()).nullish(),
  ipAddressesOrSubnets: z.array(z.string()).nullish(),
  portFilter: z.array(z.number()).nullish(),
  macAddresses: z.array(z.string()).nullish(),
});
export type AclEndpoint = z.infer<typeof aclEndpointSchema>;

export const aclRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  /** `IPV4` or `MAC`. */
  type: z.string(),
  action: z.string(),
  enabled: z.boolean(),
  index: z.number().optional(),
  sourceFilter: aclEndpointSchema.nullish(),
  destinationFilter: aclEndpointSchema.nullish(),
  metadata: originSchema,
});
export type AclRule = z.infer<typeof aclRuleSchema>;

/** DNS policies have no name: a record is its type, domain and value. */
export const dnsPolicySchema = z.object({
  id: z.string(),
  type: z.string(),
  enabled: z.boolean(),
  domain: z.string().optional(),
  ipv4Address: z.string().optional(),
  ipv6Address: z.string().optional(),
  ipAddress: z.string().optional(),
  targetDomain: z.string().optional(),
  mailServerDomain: z.string().optional(),
  serverDomain: z.string().optional(),
  text: z.string().optional(),
});
export type DnsPolicy = z.infer<typeof dnsPolicySchema>;

const listItemValue = z.union([z.string(), z.number()]);
/** `IPV4_ADDRESSES`, `IPV6_ADDRESSES` or `PORTS`, with what it matches. */
export const trafficListSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  items: z.array(
    z.object({
      type: z.string(),
      value: listItemValue.optional(),
      start: listItemValue.optional(),
      stop: listItemValue.optional(),
    }),
  ),
});
export type TrafficList = z.infer<typeof trafficListSchema>;

/** A created object: unifi-mcp reads only its id. */
export const createdSchema = z.object({ id: z.string() });

export const dpiNameSchema = z.object({ id: z.number(), name: z.string() });
export type DpiName = z.infer<typeof dpiNameSchema>;

/** A policy the API can't name (an IPS auto-block) is a null in the ordering. */
const orderedIds = z.array(z.string().nullable());
export const policyOrderingSchema = z.object({
  orderedFirewallPolicyIds: z.object({
    beforeSystemDefined: orderedIds,
    afterSystemDefined: orderedIds,
  }),
});
export type PolicyOrdering = z.infer<typeof policyOrderingSchema>;

// ---- Site Manager ----------------------------------------------------------

export const hostSchema = z.object({
  id: z.string(),
  type: z.string(),
  ipAddress: z.string().optional(),
  isBlocked: z.boolean().optional(),
  lastConnectionStateChange: z.string().optional(),
  reportedState: z
    .object({
      name: z.string().optional(),
      state: z.string().optional(),
      version: z.string().optional(),
      ip: z.string().optional(),
    })
    .optional(),
});
export type Host = z.infer<typeof hostSchema>;

const ispPeriodSchema = z.object({
  metricTime: z.string(),
  data: z.object({
    wan: z.object({
      avgLatency: z.number().optional(),
      maxLatency: z.number().optional(),
      packetLoss: z.number().optional(),
      uptime: z.number().optional(),
      downtime: z.number().optional(),
      download_kbps: z.number().optional(),
      upload_kbps: z.number().optional(),
      ispName: z.string().optional(),
    }),
  }),
});
export const ispMetricsSchema = z.object({
  metricType: z.string(),
  hostId: z.string(),
  siteId: z.string(),
  periods: z.array(ispPeriodSchema),
});
export type IspMetrics = z.infer<typeof ispMetricsSchema>;

export const siteManagerEnvelope = <T extends z.ZodType>(item: T) =>
  z.object({ data: z.array(item), nextToken: z.string().optional() });

/**
 * A whole network or WiFi broadcast as GET /{networks,wifi/broadcasts}/{id}
 * returns it, every field kept. The official PUT replaces the object, so an
 * update must send back what it was not asked to change; a schema that
 * dropped unknown fields would wipe them. Only `id` and `name` are read.
 */
export const fullObjectSchema = z.looseObject({ id: z.string(), name: z.string() });
export type FullObject = z.infer<typeof fullObjectSchema>;
/** As FullObject, for objects without a name (DNS policies). */
export const anyObjectSchema = z.looseObject({ id: z.string() });
export type AnyObject = z.infer<typeof anyObjectSchema>;

/** `Hotspot voucher details`: the fields unifi-mcp shows. */
export const voucherSchema = z.object({
  id: z.string(),
  name: z.string(),
  code: z.string().optional(),
  createdAt: z.string().optional(),
  expired: z.boolean().optional(),
  timeLimitMinutes: z.number().optional(),
  authorizedGuestLimit: z.number().optional(),
  authorizedGuestCount: z.number().optional(),
  dataUsageLimitMBytes: z.number().optional(),
  expiresAt: z.string().optional(),
});
export type Voucher = z.infer<typeof voucherSchema>;

export const voucherCreationSchema = z.object({ vouchers: z.array(voucherSchema) });
export const voucherDeletionSchema = z.object({ vouchersDeleted: z.number().optional() });
