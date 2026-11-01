import { UnifiApiError } from '../http/errors.js';
import type { KnownClient, NetworkConf, PortForward, Setting, WlanConf } from './legacy.js';
import { groupPolicies, pairsOf, type FirewallNames } from './firewall-view.js';
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
  | {
      zones: FirewallZone[];
      policies: FirewallPolicy[];
      /** Official networks, to name a zone's networks; ids are shown without. */
      networks?: Array<{ id: string; name: string }>;
      /** Official WANs: the External zone's networks, the internet in a filter. */
      wans?: Array<{ id: string; name: string }>;
    }
  /** Why the zone rules could not run: Zone-Based Firewall is off, or an endpoint changed. */
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
    deps.official.listNetworks(site.id),
    deps.official.listWans(site.id),
  ]).then(
    ([zones, policies, networks, wans]) => ({
      zones,
      policies,
      networks: networks.map((n) => ({ id: n.id, name: n.name })),
      wans: wans.map((w) => ({ id: w.id, name: w.name })),
    }),
    (error: unknown) => {
      // ZBF off, or a firewall endpoint this firmware moved: the zone rules are
      // skipped with the reason, and every other rule still runs.
      if (
        error instanceof UnifiApiError &&
        (error.kind === 'zbf-disabled' || error.kind === 'endpoint-changed')
      )
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
    } else if (w.security === 'wep') {
      finding('HIGH', 'WEP encryption is broken: its key can be recovered in minutes');
    } else if (w.wpa_mode === 'wpa1') {
      finding('HIGH', 'WPA1 (TKIP) only: an obsolete cipher; use WPA2 or WPA2/WPA3');
    } else if (w.wpa_mode === 'auto') {
      finding(
        'MEDIUM',
        'WPA/WPA2 mixed mode keeps TKIP enabled for old clients; use WPA2 or WPA2/WPA3',
      );
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
  if (LESS_TRUSTED.test(name)) return 1;
  if (name === 'internal' || name === 'gateway') return 3;
  return 2;
}

const LESS_TRUSTED = /hotspot|guest|iot|dmz|untrusted|camera|cctv/i;

/** A network by its name or legacy purpose: 0 for a WAN, 1 for IoT, guest and the like, else 3 (a LAN). */
function networkTrust(name: string, input: PostureInput): number {
  const purpose = input.networks.find((n) => n.name === name)?.purpose;
  if (purpose === 'wan') return 0;
  return LESS_TRUSTED.test(name) || purpose === 'guest' ? 1 : 3;
}

type ZoneData = Extract<FirewallView, { zones: FirewallZone[] }>;

function viewNames(fw: ZoneData): FirewallNames {
  const named = [...(fw.networks ?? []), ...(fw.wans ?? [])];
  return {
    zone: (id) => fw.zones.find((z) => z.id === id)?.name,
    network: (id) => named.find((n) => n.id === id)?.name,
    list: () => undefined,
  };
}

/** A side's network ids when a NETWORK filter names them, else undefined (the zone decides). */
function filteredNetworks(side: FirewallPolicy['source']): string[] | undefined {
  const f = side.trafficFilter;
  if (f?.type !== 'NETWORK' || !f.networkFilter || f.networkFilter.matchOpposite) return undefined;
  return f.networkFilter.networkIds.length ? f.networkFilter.networkIds : undefined;
}

/**
 * How trusted a side is, and its label. A NETWORK filter is judged within its
 * zone: a source is no more trusted than its zone or its least trusted
 * network, a destination is as trusted as its most trusted network. An id that
 * resolves to no network (or WAN) takes the zone's trust.
 */
function side(
  p: FirewallPolicy['source'],
  role: 'source' | 'destination',
  fw: ZoneData,
  input: PostureInput,
) {
  const names = viewNames(fw);
  const zone = fw.zones.find((z) => z.id === p.zoneId);
  const zoneTrust = trust(zone);
  const ids = filteredNetworks(p);
  if (!ids)
    return { known: zone !== undefined, trust: zoneTrust, label: zone?.name ?? 'unknown zone' };
  const nets = ids.map((id) => {
    const name = names.network(id);
    if (name === undefined) return { label: id, trust: zoneTrust, unresolved: true };
    const wan = fw.wans?.some((w) => w.id === id);
    return { label: name, trust: wan ? 0 : networkTrust(name, input) };
  });
  const trusts = nets.map((n) => n.trust);
  return {
    known: zone !== undefined || nets.every((n) => !n.unresolved),
    trust: role === 'source' ? Math.min(zoneTrust, ...trusts) : Math.max(...trusts),
    label: nets.map((n) => n.label).join(', '),
  };
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
  const fw = input.firewall;
  const out: Finding[] = [];
  for (const p of userAllows(fw.policies)) {
    const src = side(p.source, 'source', fw, input);
    const dst = side(p.destination, 'destination', fw, input);
    const pair = `${src.label} → ${dst.label}`;
    const object = p.name ?? p.id;
    const from = src.trust;
    const to = dst.trust;
    if (src.known && dst.known && from <= 1 && to > from) {
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

/**
 * Networks of different trust in one zone: a zone is the unit policies apply
 * to, so the zone's own pair (Internal → Internal) decides what the IoT
 * devices can reach, and UniFi's default there allows everything.
 */
function mixedTrustFindings(input: PostureInput): Finding[] {
  if ('unavailable' in input.firewall) return [];
  const fw = input.firewall;
  const names = viewNames(fw);
  const out: Finding[] = [];
  for (const zone of fw.zones) {
    const nets = zone.networkIds.map((id) => names.network(id) ?? id);
    const low = nets.filter((n) => networkTrust(n, input) === 1);
    const lan = nets.filter((n) => networkTrust(n, input) > 1);
    if (low.length === 0 || lan.length === 0) continue;
    const openDefault = fw.policies.find(
      (p) =>
        p.source.zoneId === zone.id &&
        p.destination.zoneId === zone.id &&
        p.enabled &&
        p.action.type === 'ALLOW' &&
        !p.source.trafficFilter &&
        !p.destination.trafficFilter &&
        !p.connectionStateFilter?.length,
    );
    const pair = `${zone.name} → ${zone.name}`;
    const reach = openDefault
      ? `"${openDefault.name}" (${pair}) lets ${low.join(', ')} devices reach them`
      : `only the ${pair} policies keep ${low.join(', ')} devices from them`;
    out.push({
      rule: 'zone-mixed-trust',
      severity: 'MEDIUM',
      object: `${zone.name} zone`,
      why: `${low.join(', ')} share${low.length === 1 ? 's' : ''} the ${zone.name} zone with ${lan.join(', ')}: ${reach}. Move ${low.join(', ')} to a zone of its own (unifi_create_firewall_zone) and allow only what it needs`,
    });
  }
  return out;
}

/** One user-defined rule present several times: in several zone pairs, or twice in one. */
function duplicateFindings(input: PostureInput): Finding[] {
  if ('unavailable' in input.firewall) return [];
  const fw = input.firewall;
  const names = viewNames(fw);
  const user = fw.policies.filter((p) => p.metadata.origin === 'USER_DEFINED');
  return groupPolicies(user)
    .filter((g) => g.length > 1)
    .map((g) => {
      const first = g[0]!;
      const pairs = pairsOf(g, names);
      const same = g.length - pairs.length;
      const byAddress = [first.source, first.destination].some(
        (s) => s.trafficFilter?.type === 'IP_ADDRESS',
      );
      const where =
        pairs.length > 1
          ? `is repeated in ${pairs.length} zone pairs (${pairs.join(', ')})`
          : `appears ${g.length} times in ${pairs[0]}`;
      const extra =
        pairs.length > 1 && same > 0
          ? `, ${same} more time${same === 1 ? '' : 's'} within a pair`
          : '';
      const idle =
        byAddress && pairs.length > 1
          ? '; copies in pairs its addresses never cross do nothing'
          : '';
      const fix = g.every((p) => p.id === undefined)
        ? 'The console gives these IPS auto-blocks no id, so remove the extra copies in the UniFi UI'
        : 'Remove the extra copies (unifi_delete_firewall_policy)';
      return {
        rule: 'duplicate-policies',
        severity: 'LOW' as const,
        object: first.name,
        why: `the same ${first.action.type} rule ${where}${extra}${idle}. ${fix}`,
      };
    });
}

// ---- (5) IDS/IPS -----------------------------------------------------------

const ipsSetting = (settings: Setting[]) => settings.find((s) => s.key === 'ips');

function ipsFindings(input: PostureInput): Finding[] {
  const s = ipsSetting(input.settings);
  if (!s) return [];
  if (s.ips_mode === undefined) {
    return [
      {
        rule: 'ips-off',
        severity: 'LOW',
        object: 'IDS/IPS',
        why: 'IDS/IPS mode unknown: the ips section has no ips_mode; check the setting in the UniFi UI, the firmware may have moved it',
      },
    ];
  }
  const mode = s.ips_mode;
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
    ...mixedTrustFindings(input),
    ...duplicateFindings(input),
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
    for (const rule of [
      'zone-allow-to-trusted',
      'policy-any-any',
      'zone-mixed-trust',
      'duplicate-policies',
    ]) {
      out.push({ rule, note: input.firewall.unavailable });
    }
  }
  if (!ipsSetting(input.settings)) {
    out.push({
      rule: 'ips-off',
      note: 'rest/setting has no ips section, so the IDS/IPS mode is unknown',
    });
  }
  return out;
}
