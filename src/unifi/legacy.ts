import { z } from 'zod';
import type { UnifiHttpClient } from '../http/client.js';
import { createEndpointGuard, type EndpointGuard } from './endpoint-guard.js';
import {
  deviceBasicSchema,
  dpiSchema,
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
  firstSeen?: number;
  lastSeen?: number;
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
  knownClients(ref: string): Promise<KnownClient[]>;
  portForwards(ref: string): Promise<PortForward[]>;
  wlanConf(ref: string): Promise<WlanConf[]>;
  networkConf(ref: string): Promise<NetworkConf[]>;
  settings(ref: string): Promise<Setting[]>;
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
    firstSeen: user.first_seen,
    lastSeen: station?.last_seen ?? user.last_seen,
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
    async knownClients(ref) {
      const [users, stations] = await Promise.all([
        rows(ref, 'rest/user', userSchema),
        rows(ref, 'stat/sta', stationSchema),
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
