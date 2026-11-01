import { z } from 'zod';
import type { UnifiHttpClient } from '../http/client.js';
import { createEndpointGuard, type EndpointGuard } from './endpoint-guard.js';
import {
  deviceBasicSchema,
  deviceSchema,
  dpiSchema,
  firewallRuleSchema,
  healthSchema,
  legacyEnvelope,
  networkConfSchema,
  portForwardSchema,
  reportRowSchema,
  rogueApSchema,
  settingSchema,
  stationSchema,
  sysInfoSchema,
  userSchema,
  wlanConfSchema,
  type DeviceBasic,
  type DpiRow,
  type FirewallRule,
  type Health,
  type NetworkConf,
  type ReportRow,
  type RogueAp,
  type Setting,
  type Station,
  type SysInfo,
  type User,
  type WlanConf,
} from './schemas.js';

export type {
  DeviceBasic,
  DpiRow,
  FirewallRule,
  Health,
  NetworkConf,
  ReportRow,
  RogueAp,
  Setting,
  Station,
  SysInfo,
  WlanConf,
};

export type ReportInterval = '5minutes' | 'hourly' | 'daily';
export type ReportScope = 'site' | 'ap' | 'user' | 'gw';

/** A client the console knows (rest/user), with its current address and network from stat/sta. */
export interface KnownClient {
  id: string;
  mac: string;
  ip?: string;
  name: string;
  networkId?: string;
  blocked: boolean;
  /** From the live station when connected, else what rest/user remembers. */
  wired?: boolean;
  firstSeen?: number;
  lastSeen?: number;
  /** Whether stat/sta lists it now; false means the fields below are what rest/user last saw. */
  connected?: boolean;
  /** MAC of the switch (wired) or AP (wireless) the client hangs off, or last hung off when offline. */
  uplinkMac?: string;
  /** Switch port, for a wired client. */
  uplinkPort?: number;
}

/** Where a device hangs: the MAC of its parent and the parent's port (stat/device `uplink`). */
export interface DeviceLink {
  mac: string;
  name?: string;
  uplinkMac?: string;
  uplinkPort?: number;
}

/** One stat/device row as the device list shows it: uplink, ports and radios. */
export interface LegacyDevice {
  mac: string;
  name?: string;
  /** `udm`, `usw`, `uap`... */
  type?: string;
  /** The parent and its port now; absent for the gateway and an offline device. */
  uplinkMac?: string;
  uplinkPort?: number;
  /** Where an offline device last hung. */
  lastUplinkMac?: string;
  lastUplinkPort?: number;
  ports: Array<{ idx: number; up: boolean; poeInUse?: boolean }>;
  radios: Array<{ radio: string; channel?: number | string; clients?: number }>;
}

export interface PortForward {
  id: string;
  name: string;
  enabled: boolean;
  /** LAN address traffic is forwarded to. */
  fwd: string;
  /** Port (or range) opened on the WAN. */
  dstPort: string;
  /** Port on the LAN host, when it differs. */
  fwdPort?: string;
  proto: string;
  /** Allowed source, `any` or an address. */
  src: string;
}

export type CmdManager = 'stamgr' | 'devmgr';
export interface CmdBody {
  cmd: 'block-sta' | 'unblock-sta' | 'kick-sta' | 'set-locate' | 'unset-locate';
  mac: string;
}

export interface LegacyApi {
  /** Runs a client or device command; resolves on `rc: ok`, rejects with the console's message otherwise. */
  cmd(ref: string, manager: CmdManager, body: CmdBody): Promise<void>;
  sysinfo(ref: string): Promise<SysInfo>;
  health(ref: string): Promise<Health[]>;
  stations(ref: string): Promise<Station[]>;
  devicesBasic(ref: string): Promise<DeviceBasic[]>;
  /** Each device's parent and parent port, from stat/device (last_uplink for an offline device). */
  deviceLinks(ref: string): Promise<DeviceLink[]>;
  /** stat/device: each device's uplink, port table and radios. */
  devices(ref: string): Promise<LegacyDevice[]>;
  /** `stations` spares a second stat/sta read when the caller already has it. */
  knownClients(ref: string, stations?: Station[]): Promise<KnownClient[]>;
  portForwards(ref: string): Promise<PortForward[]>;
  wlanConf(ref: string): Promise<WlanConf[]>;
  networkConf(ref: string): Promise<NetworkConf[]>;
  settings(ref: string): Promise<Setting[]>;
  firewallRules(ref: string): Promise<FirewallRule[]>;
  siteDpi(ref: string): Promise<DpiRow[]>;
  /** `macs` limits it to those clients; DPI per client is only kept for clients that asked. */
  stationDpi(ref: string, macs?: string[]): Promise<DpiRow[]>;
  rogueAps(ref: string): Promise<RogueAp[]>;
  report(
    ref: string,
    interval: ReportInterval,
    scope: ReportScope,
    range: { start: number; end: number },
    attrs: string[],
  ): Promise<ReportRow[]>;
}

function nonEmpty(value: string | undefined): string | undefined {
  return value ? value : undefined;
}

/**
 * Where a client hangs: the live station when it is connected, else where
 * rest/user last saw it, so an offline k3s node still marks its switch port.
 */
function uplinkOf(
  user: User,
  station: Station | undefined,
): Pick<KnownClient, 'uplinkMac' | 'uplinkPort'> {
  if (station) {
    return {
      uplinkMac: nonEmpty(station.sw_mac) ?? nonEmpty(station.ap_mac),
      uplinkPort: station.sw_port,
    };
  }
  return {
    uplinkMac: nonEmpty(user.last_uplink_mac),
    // A wireless client's remembered "port" is not a switch port.
    uplinkPort: user.is_wired === false ? undefined : user.last_uplink_remote_port,
  };
}

function toKnownClient(user: User, station: Station | undefined): KnownClient {
  return {
    id: user._id,
    mac: user.mac,
    ip:
      nonEmpty(station?.ip) ??
      nonEmpty(station?.last_ip) ??
      nonEmpty(user.last_ip) ??
      nonEmpty(user.fixed_ip),
    name:
      nonEmpty(user.name) ??
      nonEmpty(user.hostname) ??
      nonEmpty(station?.name) ??
      nonEmpty(station?.hostname) ??
      user.mac,
    networkId: nonEmpty(station?.network_id) ?? nonEmpty(user.last_connection_network_id),
    blocked: user.blocked ?? false,
    wired: station?.is_wired ?? user.is_wired,
    firstSeen: user.first_seen,
    lastSeen: station?.last_seen ?? user.last_seen,
    connected: station !== undefined,
    ...uplinkOf(user, station),
  };
}

export function createLegacyApi(client: UnifiHttpClient, guard?: EndpointGuard): LegacyApi {
  const g = guard ?? createEndpointGuard(client);

  async function rows<T extends z.ZodType>(
    ref: string,
    endpoint: string,
    schema: T,
    post?: unknown,
  ): Promise<z.infer<T>[]> {
    const body = await g.call({
      api: 'legacy',
      ref,
      method: post === undefined ? 'GET' : 'POST',
      endpoint,
      body: post,
      schema: legacyEnvelope(schema),
    });
    return body.data;
  }

  return {
    async cmd(ref, manager, body) {
      await rows(ref, `cmd/${manager}`, z.unknown(), body);
    },
    async sysinfo(ref) {
      const body = await g.call({
        api: 'legacy',
        ref,
        method: 'GET',
        endpoint: 'stat/sysinfo',
        schema: legacyEnvelope(sysInfoSchema).refine((b) => b.data.length > 0),
      });
      const info = body.data[0] as SysInfo;
      g.rememberVersion(ref, info.version);
      return info;
    },
    health: (ref) => rows(ref, 'stat/health', healthSchema),
    stations: (ref) => rows(ref, 'stat/sta', stationSchema),
    devicesBasic: (ref) => rows(ref, 'stat/device-basic', deviceBasicSchema),
    async deviceLinks(ref) {
      const devices = await rows(ref, 'stat/device', deviceSchema);
      return devices.map((d) => {
        const up = d.uplink?.uplink_mac ? d.uplink : d.last_uplink;
        return {
          mac: d.mac,
          name: nonEmpty(d.name),
          uplinkMac: nonEmpty(up?.uplink_mac),
          uplinkPort: up?.uplink_remote_port,
        };
      });
    },
    async devices(ref) {
      const devices = await rows(ref, 'stat/device', deviceSchema);
      return devices.map((d) => {
        const now = nonEmpty(d.uplink?.uplink_mac);
        return {
          mac: d.mac,
          name: nonEmpty(d.name),
          type: nonEmpty(d.type),
          uplinkMac: now,
          uplinkPort: now ? d.uplink?.uplink_remote_port : undefined,
          lastUplinkMac: nonEmpty(d.last_uplink?.uplink_mac),
          lastUplinkPort: d.last_uplink?.uplink_remote_port,
          ports: (d.port_table ?? []).map((p) => ({
            idx: p.port_idx,
            up: p.up,
            // Only a PoE-capable port says whether it is powering something.
            poeInUse: p.port_poe ? (p.poe_good ?? Number(p.poe_power ?? 0) > 0) : undefined,
          })),
          radios: (d.radio_table_stats ?? []).map((r) => ({
            radio: r.radio,
            channel: r.channel,
            clients: r.num_sta,
          })),
        };
      });
    },
    async knownClients(ref, known) {
      const [users, stations] = await Promise.all([
        rows(ref, 'rest/user', userSchema),
        known ?? rows(ref, 'stat/sta', stationSchema),
      ]);
      const byMac = new Map(stations.map((s) => [s.mac, s]));
      return users.map((u) => toKnownClient(u, byMac.get(u.mac)));
    },
    async portForwards(ref) {
      const forwards = await rows(ref, 'rest/portforward', portForwardSchema);
      return forwards.map((f) => ({
        id: f._id,
        name: f.name,
        enabled: f.enabled,
        fwd: f.fwd,
        dstPort: f.dst_port,
        fwdPort: f.fwd_port,
        proto: f.proto,
        src: f.src ?? 'any',
      }));
    },
    wlanConf: (ref) => rows(ref, 'rest/wlanconf', wlanConfSchema),
    networkConf: (ref) => rows(ref, 'rest/networkconf', networkConfSchema),
    settings: (ref) => rows(ref, 'rest/setting', settingSchema),
    firewallRules: (ref) => rows(ref, 'rest/firewallrule', firewallRuleSchema),
    siteDpi: (ref) => rows(ref, 'stat/sitedpi', dpiSchema),
    stationDpi: (ref, macs) =>
      rows(ref, 'stat/stadpi', dpiSchema, { type: 'by_app', ...(macs ? { macs } : {}) }),
    rogueAps: (ref) => rows(ref, 'stat/rogueap', rogueApSchema),
    report: (ref, interval, scope, range, attrs) =>
      rows(ref, `stat/report/${interval}.${scope}`, reportRowSchema, {
        attrs,
        start: range.start,
        end: range.end,
      }),
  };
}
