// Zone policies as one readable line: `Internal → External: BLOCK from
// 192.168.10.3 to 203.0.113.1 "name"`. Shared by unifi_list_firewall and the
// firewall write tools' previews and results.

import { policyFilterSchema, type DnsPolicy, type PolicyFilter } from './schemas.js';

/** How ids become names in a rule line; an unknown id is shown as it is. */
export interface FirewallNames {
  zone(id: string): string | undefined;
  network(id: string): string | undefined;
  list(id: string): string | undefined;
}

/** A policy as the console returns it or as a caller builds it (fields unchecked). */
export interface PolicyLike {
  name?: string;
  enabled?: boolean;
  action?: { type?: string };
  source?: { zoneId?: string; trafficFilter?: unknown };
  destination?: { zoneId?: string; trafficFilter?: unknown };
  connectionStateFilter?: string[];
  ipProtocolScope?: { ipVersion?: string; protocolFilter?: unknown };
}

const not = (opposite: boolean | undefined) => (opposite ? 'not ' : '');

function ipItems(items: NonNullable<NonNullable<PolicyFilter['ipAddressFilter']>['items']>) {
  return items
    .map((i) => (i.value !== undefined ? i.value : `${i.start ?? '?'}–${i.stop ?? '?'}`))
    .join(',');
}

function ports(filter: PolicyFilter['portFilter'], names: FirewallNames): string | undefined {
  if (!filter) return undefined;
  if (filter.trafficMatchingListId !== undefined) {
    const list = names.list(filter.trafficMatchingListId) ?? filter.trafficMatchingListId;
    return `${not(filter.matchOpposite)}ports in list "${list}"`;
  }
  const values = (filter.items ?? []).map((i) =>
    i.value !== undefined ? String(i.value) : `${i.start ?? '?'}–${i.stop ?? '?'}`,
  );
  return `${not(filter.matchOpposite)}port${values.length === 1 ? '' : 's'} ${values.join(',')}`;
}

/** What a side's filter matches, or undefined for none (the whole zone). */
export function filterText(raw: unknown, names: FirewallNames): string | undefined {
  if (raw == null) return undefined;
  const parsed = policyFilterSchema.safeParse(raw);
  if (!parsed.success) return '[filtered]';
  const f = parsed.data;
  const parts: string[] = [];
  if (f.networkFilter) {
    const nets = f.networkFilter.networkIds.map((id) => names.network(id) ?? id).join(', ');
    parts.push(`${not(f.networkFilter.matchOpposite)}${nets}`);
  } else if (f.ipAddressFilter) {
    const a = f.ipAddressFilter;
    const what =
      a.trafficMatchingListId !== undefined
        ? `list "${names.list(a.trafficMatchingListId) ?? a.trafficMatchingListId}"`
        : ipItems(a.items ?? []);
    parts.push(`${not(a.matchOpposite)}${what}`);
  } else if (!f.portFilter) {
    parts.push(`[${f.type.toLowerCase().replace(/_/g, ' ')}]`);
  }
  const p = ports(f.portFilter, names);
  if (p) parts.push(p);
  return parts.join(' ');
}

function protocolText(scope: PolicyLike['ipProtocolScope']): string {
  const f = scope?.protocolFilter as
    | {
        type?: string;
        matchOpposite?: boolean;
        protocol?: { name?: string };
        preset?: { name?: string };
        protocolNumber?: number;
      }
    | undefined;
  const version = scope?.ipVersion === 'IPV6' ? ' IPv6' : '';
  if (!f || typeof f !== 'object') return version;
  const name =
    f.protocol?.name ??
    f.preset?.name ??
    (f.protocolNumber !== undefined ? `protocol ${f.protocolNumber}` : f.type);
  return `${version} ${not(f.matchOpposite)}${String(name ?? 'filtered').toLowerCase()}`;
}

/** `BLOCK from X to Y udp [INVALID] "name"`: everything but the zone pair. */
export function policyMatch(p: PolicyLike, names: FirewallNames, opts: { name?: boolean } = {}) {
  const from = filterText(p.source?.trafficFilter, names);
  const to = filterText(p.destination?.trafficFilter, names);
  const where = [from && `from ${from}`, to && `to ${to}`].filter(Boolean).join(' ') || 'all';
  const states = p.connectionStateFilter?.length ? ` [${p.connectionStateFilter.join(',')}]` : '';
  const name = opts.name === false || !p.name ? '' : ` "${p.name}"`;
  return `${p.action?.type ?? '?'} ${where}${protocolText(p.ipProtocolScope)}${states}${name}`;
}

export const zonePair = (p: PolicyLike, names: FirewallNames) => {
  const zone = (id: string | undefined) => (id === undefined ? '?' : (names.zone(id) ?? id));
  return `${zone(p.source?.zoneId)} → ${zone(p.destination?.zoneId)}`;
};

/** `Internal → External: BLOCK all "name"`, `(disabled)` when off. */
export function policyRule(p: PolicyLike, names: FirewallNames, opts: { name?: boolean } = {}) {
  const off = p.enabled === false ? ' (disabled)' : '';
  return `${zonePair(p, names)}: ${policyMatch(p, names, opts)}${off}`;
}

/** The field that holds each record type's value. */
const VALUE_FIELD: Record<string, keyof DnsPolicy> = {
  A_RECORD: 'ipv4Address',
  AAAA_RECORD: 'ipv6Address',
  CNAME_RECORD: 'targetDomain',
  MX_RECORD: 'mailServerDomain',
  SRV_RECORD: 'serverDomain',
  TXT_RECORD: 'text',
  FORWARD_DOMAIN: 'ipAddress',
};

/** `A_RECORD nas.home.arpa → 192.168.10.3`: DNS policies have no name. */
export function dnsRecord(d: Partial<DnsPolicy> & { type?: string }): string {
  const field = VALUE_FIELD[d.type ?? ''];
  const value = field === undefined ? undefined : d[field];
  return `${d.type ?? '?'} ${d.domain ?? '?'}${value === undefined ? '' : ` → ${String(value)}`}`;
}

/** Everything that makes two policies the same rule, except the zone pair they sit in. */
function signature(p: PolicyLike & { metadata?: { origin?: string } }): string {
  return JSON.stringify([
    p.name,
    p.enabled,
    p.action?.type,
    p.source?.trafficFilter ?? null,
    p.destination?.trafficFilter ?? null,
    p.ipProtocolScope ?? null,
    p.connectionStateFilter ?? null,
    p.metadata?.origin,
  ]);
}

/**
 * Policies that are the same rule in several zone pairs (or twice in one), in
 * console order: the Zone-Based Firewall migration copied each IPS block into
 * every pair, and UniFi's own defaults repeat per pair by design.
 */
export function groupPolicies<T extends PolicyLike & { metadata?: { origin?: string } }>(
  policies: T[],
): T[][] {
  const groups = new Map<string, T[]>();
  for (const p of policies) {
    const key = signature(p);
    const group = groups.get(key);
    if (group) group.push(p);
    else groups.set(key, [p]);
  }
  return [...groups.values()];
}

/** The distinct zone pairs of a group, in order. */
export const pairsOf = (group: PolicyLike[], names: FirewallNames) => [
  ...new Set(group.map((p) => zonePair(p, names))),
];
