// What every firewall write tool reads first, and the lookups and refusals
// they share. Reading the zones and policies first means a console with
// Zone-Based Firewall off answers every firewall tool with the zbf-disabled
// message (Review Focus 5) before anything is sent.

import { z } from 'zod';
import type { FirewallNames } from '../firewall-view.js';
import { zonePair } from '../firewall-view.js';
import type { Target } from '../guard.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { FirewallPolicy, FirewallZone, OfficialNetwork, TrafficList } from '../official.js';
import type { FirewallContext, PolicyTarget } from '../policy-scope.js';
import type { Site } from '../sites.js';
import type { WriteDeps } from './common.js';
import { diff, merge, type Change, type Plain } from './objects.js';

export interface FirewallState extends FirewallContext {
  policies: FirewallPolicy[];
  networks: OfficialNetwork[];
}

export async function loadFirewall(deps: WriteDeps, site: Site): Promise<FirewallState> {
  const [zones, policies, trafficLists, networks] = await Promise.all([
    deps.official.listFirewallZones(site.id),
    deps.official.listFirewallPolicies(site.id),
    deps.official.listTrafficLists(site.id),
    deps.official.listNetworks(site.id),
  ]);
  return { zones, policies, trafficLists, networks };
}

export function namesOf(
  state: Pick<FirewallState, 'zones' | 'networks' | 'trafficLists'>,
): FirewallNames {
  return {
    zone: (id) => state.zones.find((z) => z.id === id)?.name,
    network: (id) => state.networks.find((n) => n.id === id)?.name,
    list: (id) => state.trafficLists.find((l) => l.id === id)?.name,
  };
}

/** A zone by id or name (any case); an unknown one is an error naming the zones. */
export function findZone(zones: FirewallZone[], query: string): FirewallZone {
  const match = lookup(zones, query, [(z, q) => sameText(z.id, q), (z, q) => sameText(z.name, q)]);
  if ('found' in match) return match.found;
  throw new Error(
    `No firewall zone matches "${query}"; the zones are: ${zones.map((z) => z.name).join(', ')}`,
  );
}

/** Network ids by id or name (any case); an unknown one is an error naming the networks. */
export function networkIds(networks: OfficialNetwork[], queries: string[]): string[] {
  return queries.map((query) => {
    const match = lookup(networks, query, [
      (n, q) => sameText(n.id, q),
      (n, q) => sameText(n.name, q),
    ]);
    if ('found' in match) return match.found.id;
    throw new Error(
      `No network matches "${query}"; the networks are: ${networks.map((n) => n.name).join(', ')}`,
    );
  });
}

const origin = (o: string) => o.toLowerCase().replace(/_/g, '-');

/** Refuses an object UniFi manages: anything not USER_DEFINED. */
export function assertUserDefined(what: string, label: string, metadata: { origin: string }): void {
  if (metadata.origin !== 'USER_DEFINED') {
    throw new Error(`${label} is a ${origin(metadata.origin)} ${what}; UniFi manages it`);
  }
}

export const policyLabel = (p: FirewallPolicy, names: FirewallNames) =>
  `"${p.name}" (${zonePair(p, names)})`;

/** A policy the API can change: it has an id and a user made it. */
export function assertChangeable(
  p: FirewallPolicy,
  names: FirewallNames,
): asserts p is FirewallPolicy & { id: string } {
  if (p.id === undefined) {
    throw new Error(
      `${policyLabel(p, names)} is an IPS auto-block the console gives no id, so the official API can't change it; UniFi manages it`,
    );
  }
  assertUserDefined('policy', policyLabel(p, names), p.metadata);
}

const policyRow = (names: FirewallNames) => (p: FirewallPolicy) => ({
  ...(p.id === undefined ? {} : { id: p.id }),
  name: p.name,
  zones: zonePair(p, names),
  origin: p.metadata.origin,
});

/**
 * A policy by id or exact name. Several matches are candidates, unless none
 * of them can be changed (the IPS auto-blocks repeat their name per zone pair).
 */
export function findPolicy(
  state: FirewallState,
  query: string,
): (FirewallPolicy & { id: string }) | ReturnType<typeof ambiguous> {
  const names = namesOf(state);
  const match = lookup(state.policies, query, [
    (p, q) => sameText(p.id, q),
    (p, q) => sameText(p.name, q),
  ]);
  if ('none' in match) {
    throw new Error(`No firewall policy matches "${query}"; unifi_list_firewall lists them`);
  }
  if ('ambiguous' in match) {
    const changeable = match.ambiguous.filter((p) => p.id !== undefined);
    if (changeable.length === 0) assertChangeable(match.ambiguous[0]!, names);
    return ambiguous(query, match.ambiguous, policyRow(names));
  }
  assertChangeable(match.found, names);
  return match.found;
}

/** Drops every null: a caller's `null` means "remove this field". */
export function dropNulls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(dropNulls);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, v]) => v !== null)
      .map(([k, v]) => [k, dropNulls(v)]),
  );
}

const without = (obj: Plain, keys: readonly string[]): Plain =>
  Object.fromEntries(Object.entries(obj).filter(([k]) => !keys.includes(k)));

/** As objects.wholeUpdate, but a null in the patch removes the field. */
export function mergeUpdate(
  current: Plain,
  patch: Plain,
  readOnly: readonly string[],
): { body: Plain; changes: Record<string, Change> } {
  const base = without(current, readOnly);
  const body = dropNulls(merge(base, without(patch, readOnly))) as Plain;
  return { body, changes: diff(base, body) };
}

/** Several policy targets as one. */
export function unionTargets(...targets: PolicyTarget[]): PolicyTarget {
  const out: Required<PolicyTarget> = {
    kind: 'policy',
    sourceNetworkIds: [],
    destNetworkIds: [],
    sourceAddresses: [],
    destAddresses: [],
    unplaced: [],
  };
  for (const t of targets) {
    for (const key of [
      'sourceNetworkIds',
      'destNetworkIds',
      'sourceAddresses',
      'destAddresses',
      'unplaced',
    ] as const) {
      for (const v of t[key] ?? []) if (!out[key].includes(v)) out[key].push(v);
    }
  }
  return out;
}

/** Policies that match on a traffic matching list, by its id. */
export function policiesUsing(policies: FirewallPolicy[], listId: string): FirewallPolicy[] {
  const uses = (side: FirewallPolicy['source']) =>
    side.trafficFilter?.ipAddressFilter?.trafficMatchingListId === listId ||
    side.trafficFilter?.portFilter?.trafficMatchingListId === listId;
  return policies.filter((p) => uses(p.source) || uses(p.destination));
}

/** IPv4 list items as the address strings policyTarget reads; undefined for others. */
export function itemAddress(item: TrafficList['items'][number]): string | undefined {
  if ((item.type === 'IP_ADDRESS' || item.type === 'SUBNET') && typeof item.value === 'string')
    return item.value;
  if (
    item.type === 'IP_ADDRESS_RANGE' &&
    typeof item.start === 'string' &&
    typeof item.stop === 'string'
  )
    return `${item.start}-${item.stop}`;
  return undefined;
}

/** A traffic filter or ACL endpoint as the official request takes it. */
export const filterInput = z.record(z.string(), z.unknown());

export type { Target };
