import type { KnownClient, PortForward } from './legacy.js';
import { coverageNote, severityRank } from './read-common.js';
import type { SyslogEntry } from './syslog.js';

export type Direction = 'inbound' | 'outbound' | 'blocked' | 'other';

export interface ThreatPortForward {
  name: string;
  /** WAN port, then `-> LAN port` when the forward changes it. */
  ports: string;
  proto: string;
  /** Allowed source, `any` when open to the internet. */
  source: string;
}

export interface ThreatGroup {
  direction: Direction;
  /**
   * The LAN client (inbound, outbound), the firewall rule and the LAN address
   * it blocked (blocked: `<trigger> -> <client> (<ip>)` on the way in or within
   * the LAN, `<trigger>, outbound from <client> (<ip>)` on the way out), or the
   * log key (other).
   */
  lanSide: string;
  count: number;
  bySeverity: Record<string, number>;
  maxSeverity: string;
  firstSeen: string;
  lastSeen: string;
  distinctRemotes: number;
  topRemotes: Array<{ ip: string; count: number }>;
  /** Enabled forwards to this client's IP: the way in for an inbound threat. */
  portForwards?: ThreatPortForward[];
  keys: string[];
}

export interface ThreatSummary {
  range: { from: string; to: string; complete: boolean; truncatedAt?: string; note?: string };
  totalEvents: number;
  groups: ThreatGroup[];
  /** The groups past `maxGroups`, summarised rather than dropped. */
  tail?: { groups: number; events: number };
  topRemotesOverall: Array<{ ip: string; count: number; lanSides: string[] }>;
}

export interface ThreatOptions {
  maxGroups: number;
  /** Set when the scan stopped at the ceiling; the oldest entry it reached. */
  truncatedAt?: number;
  range: { from: number; to: number };
}

const TOP_REMOTES = 5;
const TOP_REMOTES_OVERALL = 10;

type Param = SyslogEntry['parameters'][string] | undefined;

interface Classified {
  direction: Direction;
  lanSide: string;
  /** Distinguishes two LAN clients that happen to share a display name. */
  lanId: string;
  /** The LAN address an inbound event reached (DST_IP): the forward match when there's no client. */
  lanIp?: string;
  remote?: string;
}

const label = (p: Param): string | undefined => p?.name || p?.id;

/**
 * A LAN-side address: RFC 1918 (10/8, 172.16/12, 192.168/16), CGNAT and
 * Tailscale (100.64/10), IPv4 link-local (169.254/16), and IPv6 ULA (fd00::/8)
 * and link-local (fe80::/10).
 */
function isPrivate(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(ip);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254)
    );
  }
  return /^fd[0-9a-f]{0,2}:/i.test(ip) || /^fe[89ab][0-9a-f]?:/i.test(ip);
}

/** `name (ip)` for a LAN address a known client holds, else the address. */
function lanAddress(ip: string, clients: KnownClient[]): string {
  const name = clients.find((k) => k.ip === ip)?.name;
  return name && name !== ip ? `${name} (${ip})` : ip;
}

function classify(e: SyslogEntry, clients: KnownClient[]): Classified {
  const p = e.parameters;
  if (e.key.endsWith('_KNOWN_DESTINATION_CLIENT')) {
    const lan = p.DST_CLIENT;
    const lanSide = label(lan) ?? label(p.DST_IP) ?? 'unknown client';
    return {
      direction: 'inbound',
      lanSide,
      lanId: lan?.id ?? lanSide,
      lanIp: p.DST_IP?.id,
      remote: label(p.SRC_IP),
    };
  }
  if (e.key.endsWith('_KNOWN_SOURCE_CLIENT')) {
    const lan = p.SRC_CLIENT;
    const lanSide = label(lan) ?? label(p.SRC_IP) ?? 'unknown client';
    return { direction: 'outbound', lanSide, lanId: lan?.id ?? lanSide, remote: label(p.DST_IP) };
  }
  if (e.key === 'TRAFFIC_BLOCKED') {
    // By rule, then by the LAN address it blocked, so one rule over many hosts
    // reads apart. A private DST is the LAN side (inbound, or LAN to LAN);
    // else a private SRC is, and the block stopped it going out.
    const trigger = p.TRIGGER?.name ?? 'firewall';
    const dst = p.DST_IP?.id;
    const src = p.SRC_IP?.id;
    const outbound = !(dst && isPrivate(dst)) && src !== undefined && isPrivate(src);
    const [ip, client, remote] = outbound
      ? [src, label(p.SRC_CLIENT), label(p.DST_IP)]
      : [dst, label(p.DST_CLIENT), label(p.SRC_IP)];
    const target =
      client && ip ? `${client} (${ip})` : (client ?? (ip ? lanAddress(ip, clients) : undefined));
    const lanSide = !target
      ? trigger
      : outbound
        ? `${trigger}, outbound from ${target}`
        : `${trigger} -> ${target}`;
    return {
      direction: 'blocked',
      lanSide,
      lanId: `${p.TRIGGER?.id ?? trigger}\u0000${outbound ? 'out' : 'in'}\u0000${ip ?? ''}`,
      remote,
    };
  }
  return { direction: 'other', lanSide: e.key, lanId: e.key, remote: label(p.SRC_IP) ?? label(p.DST_IP) };
}

interface Acc {
  c: Classified;
  count: number;
  bySeverity: Record<string, number>;
  max: SyslogEntry['severity'];
  first: number;
  last: number;
  remotes: Map<string, number>;
  keys: Set<string>;
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const byIp = (a: string, b: string) => a.localeCompare(b, 'en', { numeric: true });
/** Most first; equal counts by IP, so the same log always gives the same list. */
const byCountThenIp = <T extends { count: number; ip: string }>(a: T, b: T) =>
  b.count - a.count || byIp(a.ip, b.ip);

function topOf(remotes: Map<string, number>, n: number) {
  return [...remotes].map(([ip, count]) => ({ ip, count })).sort(byCountThenIp).slice(0, n);
}

function describeForward(f: PortForward): ThreatPortForward {
  const ports = f.fwdPort && f.fwdPort !== f.dstPort ? `${f.dstPort} -> ${f.fwdPort}` : f.dstPort;
  return { name: f.name, ports, proto: f.proto, source: f.src };
}

/**
 * Enabled forwards to an inbound client, matched by the client's IP, never by
 * its name; without a known client, by the event's DST_IP (as posture does).
 */
function forwardsFor(acc: Acc, forwards: PortForward[], clients: KnownClient[]) {
  if (acc.c.direction !== 'inbound') return undefined;
  const ip =
    clients.find((k) => k.mac.toLowerCase() === acc.c.lanId.toLowerCase())?.ip ?? acc.c.lanIp;
  if (!ip) return undefined;
  const matched = forwards.filter((f) => f.enabled && f.fwd === ip).map(describeForward);
  return matched.length ? matched : undefined;
}

/**
 * Groups SECURITY log entries by (direction, LAN side) and ranks the groups
 * by worst severity, then count. Nothing is dropped: groups past `maxGroups`
 * become the `tail`, and a scan cut at the ceiling is marked incomplete.
 */
export function summariseThreats(
  entries: SyslogEntry[],
  forwards: PortForward[],
  clients: KnownClient[],
  opts: ThreatOptions,
): ThreatSummary {
  const groups = new Map<string, Acc>();
  const remotesOverall = new Map<string, { count: number; lanSides: Set<string> }>();
  let total = 0;

  for (const e of entries) {
    if (e.category !== 'SECURITY') continue;
    total++;
    const c = classify(e, clients);
    const id = `${c.direction}\u0000${c.lanId}`;
    let acc = groups.get(id);
    if (!acc) {
      acc = { c, count: 0, bySeverity: {}, max: e.severity, first: e.timestamp, last: e.timestamp, remotes: new Map(), keys: new Set() };
      groups.set(id, acc);
    }
    acc.count++;
    acc.bySeverity[e.severity] = (acc.bySeverity[e.severity] ?? 0) + 1;
    if (severityRank(e.severity) > severityRank(acc.max)) acc.max = e.severity;
    acc.first = Math.min(acc.first, e.timestamp);
    acc.last = Math.max(acc.last, e.timestamp);
    acc.keys.add(e.key);
    if (c.remote) {
      acc.remotes.set(c.remote, (acc.remotes.get(c.remote) ?? 0) + 1);
      const overall = remotesOverall.get(c.remote) ?? { count: 0, lanSides: new Set<string>() };
      overall.count++;
      overall.lanSides.add(c.lanSide);
      remotesOverall.set(c.remote, overall);
    }
  }

  const ranked = [...groups.values()].sort(
    (a, b) =>
      severityRank(b.max) - severityRank(a.max) ||
      b.count - a.count ||
      byText(a.c.lanSide, b.c.lanSide) ||
      byText(a.c.direction, b.c.direction),
  );
  const shown = ranked.slice(0, opts.maxGroups);
  const rest = ranked.slice(opts.maxGroups);

  return {
    range: {
      from: new Date(opts.range.from).toISOString(),
      to: new Date(opts.range.to).toISOString(),
      complete: opts.truncatedAt === undefined,
      ...(opts.truncatedAt === undefined
        ? {}
        : { truncatedAt: new Date(opts.truncatedAt).toISOString(), note: coverageNote(opts.truncatedAt) }),
    },
    totalEvents: total,
    groups: shown.map((acc) => {
      const portForwards = forwardsFor(acc, forwards, clients);
      return {
        direction: acc.c.direction,
        lanSide: acc.c.lanSide,
        count: acc.count,
        bySeverity: acc.bySeverity,
        maxSeverity: acc.max,
        firstSeen: new Date(acc.first).toISOString(),
        lastSeen: new Date(acc.last).toISOString(),
        distinctRemotes: acc.remotes.size,
        topRemotes: topOf(acc.remotes, TOP_REMOTES),
        ...(portForwards ? { portForwards } : {}),
        keys: [...acc.keys].sort(),
      };
    }),
    ...(rest.length
      ? { tail: { groups: rest.length, events: rest.reduce((n, g) => n + g.count, 0) } }
      : {}),
    topRemotesOverall: [...remotesOverall]
      .map(([ip, r]) => ({ ip, count: r.count, lanSides: [...r.lanSides].sort() }))
      .sort(byCountThenIp)
      .slice(0, TOP_REMOTES_OVERALL),
  };
}
