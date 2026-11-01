import { UnifiApiError } from '../http/errors.js';
import type { KnownClient, NetworkConf, PortForward, Setting, WlanConf } from './legacy.js';
import type { FirewallPolicy, FirewallZone, OfficialDevice } from './official.js';
import { DAY_MS, EVENT_CEILING, severityRank, type ReadDeps } from './read-common.js';
import { iso } from './shape.js';
import type { Site } from './sites.js';
import type { SyslogEntry } from './syslog.js';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH';

export interface Finding {
  rule: string;
  severity: Severity;
  object: string;
  why: string;
}

export type FirewallView =
  | { zones: FirewallZone[]; policies: FirewallPolicy[] }
  /** Zone-Based Firewall is off: why the zone rules could not run. */
  | { unavailable: string };

/** Everything the audit reads, fetched once by `loadPostureInput` so the rules stay pure. */
export interface PostureInput {
  now: number;
  /** `new-clients` window. */
  newClientDays: number;
  portForwards: PortForward[];
  wlans: WlanConf[];
  networks: NetworkConf[];
  settings: Setting[];
  firewall: FirewallView;
  devices: OfficialDevice[];
  clients: KnownClient[];
  /** SECURITY log entries over the last `days`; `truncatedAt` when the scan hit the ceiling. */
  threats: { entries: SyslogEntry[]; days: number; truncatedAt?: number };
}

const SEVERITY_ORDER: Severity[] = ['HIGH', 'MEDIUM', 'LOW'];

export async function loadPostureInput(
  deps: ReadDeps,
  site: Site,
  opts: { newClientDays: number; threatDays: number },
): Promise<PostureInput> {
  const now = (deps.now ?? Date.now)();
  const firewall: Promise<FirewallView> = Promise.all([
    deps.official.listFirewallZones(site.id),
    deps.official.listFirewallPolicies(site.id),
  ]).then(
    ([zones, policies]) => ({ zones, policies }),
    (error: unknown) => {
      if (error instanceof UnifiApiError && error.kind === 'zbf-disabled')
        return { unavailable: error.message };
      throw error;
    },
  );
  const [portForwards, wlans, networks, settings, fw, devices, clients, scan] = await Promise.all([
    deps.legacy.portForwards(site.ref),
    deps.legacy.wlanConf(site.ref),
    deps.legacy.networkConf(site.ref),
    deps.legacy.settings(site.ref),
    firewall,
    deps.official.listDevices(site.id),
    deps.legacy.knownClients(site.ref),
    deps.syslog.scan(site.ref, {
      from: now - opts.threatDays * DAY_MS,
      to: now,
      ceiling: EVENT_CEILING,
      filter: (e) => e.category === 'SECURITY',
    }),
  ]);
  return {
    now,
    newClientDays: opts.newClientDays,
    portForwards,
    wlans,
    networks,
    settings,
    firewall: fw,
    devices,
    clients,
    threats: { entries: scan.entries, days: opts.threatDays, truncatedAt: scan.truncatedAt },
  };
}

// ---- (1) port forwards -------------------------------------------------------

const OPEN_SOURCES = new Set(['', 'any', '0.0.0.0/0']);

/** Inbound threat events per LAN IP. The log names the target by MAC, so the MAC is mapped to its IP. */
function inboundByIp(entries: SyslogEntry[], clients: KnownClient[]) {
  const ipOfMac = new Map(
    clients.filter((c) => c.ip).map((c) => [c.mac.toLowerCase(), c.ip as string]),
  );
  const counts = new Map<string, { count: number; max: SyslogEntry['severity'] }>();
  for (const e of entries) {
    if (e.category !== 'SECURITY' || !e.key.endsWith('_KNOWN_DESTINATION_CLIENT')) continue;
    const target = e.parameters.DST_CLIENT?.id;
    const ip = (target && ipOfMac.get(target.toLowerCase())) ?? e.parameters.DST_IP?.id;
    if (!ip) continue;
    const c = counts.get(ip) ?? { count: 0, max: e.severity };
    c.count++;
    if (severityRank(e.severity) > severityRank(c.max)) c.max = e.severity;
    counts.set(ip, c);
  }
  return counts;
}

function portForwardFindings(input: PostureInput): Finding[] {
  const threats = inboundByIp(input.threats.entries, input.clients);
  const floor = input.threats.truncatedAt === undefined ? '' : 'at least ';
  return input.portForwards
    .filter((f) => f.enabled && OPEN_SOURCES.has(f.src.trim().toLowerCase()))
    .map((f) => {
      const lan = f.fwdPort && f.fwdPort !== f.dstPort ? `${f.fwd}:${f.fwdPort}` : f.fwd;
      const client = input.clients.find((c) => c.ip === f.fwd);
      const target = client ? `${client.name} (${f.fwd})` : `${f.fwd} (no known client)`;
      const t = threats.get(f.fwd);
      const seen = t
        ? `${floor}${t.count} inbound threat events (worst ${t.max})`
        : `${floor === '' ? 'no' : 'no counted'} inbound threat events`;
      return {
        rule: 'port-forward-open',
        severity: 'HIGH' as const,
        object: f.name,
        why: `WAN ${f.dstPort} → ${lan} (${f.proto}) is open to any source; its target ${target} drew ${seen} in the last ${input.threats.days} days`,
      };
    });
}

// ---- (2) WiFi --------------------------------------------------------------

/** WiFi 6/6E/7 and the Wave 2 HD/XG models; older APs are left out rather than guessed at. */
const WPA3_CAPABLE =
  /^(U6|U7|E7|UK|UAP[- ]?(nanoHD|FlexHD|HD|SHD|BeaconHD|IW[- ]?HD|XG)|UWB[- ]?XG)/i;

function wifiFindings(input: PostureInput): Finding[] {
  const wpa3Aps = input.devices
    .filter((d) => d.features?.includes('accessPoint') && WPA3_CAPABLE.test(d.model))
    .map((d) => d.name);
  const out: Finding[] = [];
  for (const w of input.wlans.filter((x) => x.enabled)) {
    const finding = (severity: Severity, why: string) =>
      out.push({ rule: 'wifi-weak', severity, object: w.name, why });
    if (w.security === 'open') {
      finding('HIGH', 'no encryption: anyone in range can join it and read its traffic');
    } else if (
      w.wpa_mode === 'wpa2' &&
      !w.wpa3_support &&
      !w.wpa3_transition &&
      wpa3Aps.length > 0
    ) {
      const verb = wpa3Aps.length === 1 ? 'supports' : 'support';
      finding(
        'MEDIUM',
        `WPA2 only, while ${wpa3Aps.join(', ')} ${verb} WPA3; WPA2/WPA3 transition mode keeps old clients working`,
      );
    }
    if (w.is_guest && !w.l2_isolation) {
      const net = input.networks.find((n) => n._id === w.networkconf_id);
      if (net?.purpose !== 'guest' && !net?.network_isolation_enabled) {
        finding(
          'MEDIUM',
          'guest SSID without client isolation: guests can reach each other and the network it bridges to',
        );
      }
    }
  }
  return out;
}

// ---- (3, 4) zone policies --------------------------------------------------

/** 0 = the internet; 1 = guest, hotspot, IoT, DMZ; 2 = VPN or a custom zone; 3 = internal and the gateway. */
function trust(zone: FirewallZone | undefined): number {
  const name = zone?.name?.toLowerCase() ?? '';
  if (name === 'external') return 0;
  if (/hotspot|guest|iot|dmz|untrusted/.test(name)) return 1;
  if (name === 'internal' || name === 'gateway') return 3;
  return 2;
}

const RETURN_STATES = new Set(['ESTABLISHED', 'RELATED']);

function userAllows(policies: FirewallPolicy[]) {
  return policies.filter(
    (p) =>
      p.enabled !== false &&
      p.action?.type?.toUpperCase() === 'ALLOW' &&
      p.metadata?.origin !== 'SYSTEM_DEFINED' &&
      !(
        p.connectionStateFilter?.length &&
        p.connectionStateFilter.every((s) => RETURN_STATES.has(s.toUpperCase()))
      ),
  );
}

function policyFindings(input: PostureInput): Finding[] {
  if ('unavailable' in input.firewall) return [];
  const zones = new Map(input.firewall.zones.map((z) => [z.id, z]));
  const out: Finding[] = [];
  for (const p of userAllows(input.firewall.policies)) {
    const src = zones.get(p.source?.zoneId ?? '');
    const dst = zones.get(p.destination?.zoneId ?? '');
    const pair = `${src?.name ?? 'unknown zone'} → ${dst?.name ?? 'unknown zone'}`;
    const object = p.name ?? p.id;
    const from = trust(src);
    const to = trust(dst);
    if (src && dst && from <= 1 && to > from) {
      out.push({
        rule: 'zone-allow-to-trusted',
        severity: from === 0 ? 'HIGH' : 'MEDIUM',
        object,
        why: `${pair}: ALLOW lets a less trusted zone into a more trusted one`,
      });
    }
    if (
      !p.source?.trafficFilter &&
      !p.destination?.trafficFilter &&
      !p.ipProtocolScope?.protocolFilter
    ) {
      out.push({
        rule: 'policy-any-any',
        severity: from === 0 ? 'HIGH' : from < to ? 'MEDIUM' : 'LOW',
        object,
        why: `${pair}: ALLOW any source, any destination, any protocol`,
      });
    }
  }
  return out;
}

// ---- (5) IDS/IPS -----------------------------------------------------------

const ipsSetting = (settings: Setting[]) => settings.find((s) => s.key === 'ips');

function ipsFindings(input: PostureInput): Finding[] {
  const s = ipsSetting(input.settings);
  if (!s) return [];
  const mode = s.ips_mode ?? 'disabled';
  const finding = (severity: Severity, why: string) => [
    { rule: 'ips-off', severity, object: 'IDS/IPS', why },
  ];
  if (mode === 'disabled')
    return finding('HIGH', 'IDS/IPS is off: threats are neither logged nor blocked');
  if (mode === 'ids')
    return finding(
      'MEDIUM',
      'IDS/IPS is in detect-only mode (IDS): threats are logged, not blocked',
    );
  if (mode === 'ips' || mode === 'ipsInline') return [];
  return finding(
    'LOW',
    `IDS/IPS mode "${mode}" is not one unifi-mcp knows; check it in the UniFi UI`,
  );
}

// ---- (6, 7) new clients, firmware -----------------------------------------

function newClientFindings(input: PostureInput): Finding[] {
  const since = (input.now - input.newClientDays * DAY_MS) / 1000;
  return input.clients
    .filter((c) => c.firstSeen !== undefined && c.firstSeen >= since)
    .sort((a, b) => (b.firstSeen ?? 0) - (a.firstSeen ?? 0))
    .map((c) => ({
      rule: 'new-clients',
      severity: 'LOW' as const,
      object: c.ip ? `${c.name} (${c.ip})` : c.name,
      why: `first seen ${iso((c.firstSeen ?? 0) * 1000)}, within the last ${input.newClientDays} days`,
    }));
}

function firmwareFindings(input: PostureInput): Finding[] {
  return input.devices
    .filter((d) => d.firmwareUpdatable)
    .map((d) => ({
      rule: 'firmware-updates',
      severity: 'LOW' as const,
      object: d.name,
      why: `firmware ${d.firmwareVersion ?? '(unknown)'} has an update available`,
    }));
}

/** Runs every rule; findings come HIGH first, then MEDIUM, then LOW, each rule's order kept. */
export function auditPosture(input: PostureInput): Finding[] {
  const all = [
    ...portForwardFindings(input),
    ...wifiFindings(input),
    ...policyFindings(input),
    ...ipsFindings(input),
    ...newClientFindings(input),
    ...firmwareFindings(input),
  ];
  return all.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
}

/** Rules that could not run on this console, and why; never a silent pass. */
export function skippedRules(input: PostureInput): Array<{ rule: string; note: string }> {
  const out: Array<{ rule: string; note: string }> = [];
  if ('unavailable' in input.firewall) {
    out.push(
      { rule: 'zone-allow-to-trusted', note: input.firewall.unavailable },
      { rule: 'policy-any-any', note: input.firewall.unavailable },
    );
  }
  if (!ipsSetting(input.settings)) {
    out.push({
      rule: 'ips-off',
      note: 'rest/setting has no ips section, so the IDS/IPS mode is unknown',
    });
  }
  return out;
}
