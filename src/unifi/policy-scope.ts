// Where a zone policy reaches, for the guard: the networks and addresses each
// side can match (R14, R19). A side that is a zone alone matches every network
// in the zone; a filter the code can place narrows it; anything else falls back
// to the whole zone (the zone bounds every filter) or, when even the zone is
// unknown, is reported as unplaced so the change leans to confirm.

import { z } from 'zod';
import type { Target } from './guard.js';
import type { FirewallZone, TrafficList } from './official.js';
import { policyFilterSchema } from './schemas.js';

export interface FirewallContext {
  zones: FirewallZone[];
  trafficLists: TrafficList[];
}

/** One policy as given (from the console or a caller): its two sides, unchecked. */
export interface PolicySides {
  source?: unknown;
  destination?: unknown;
}

export type PolicyTarget = Extract<Target, { kind: 'policy' }>;

interface Placed {
  networkIds: string[];
  addresses: string[];
  unplaced: string[];
}

const sideSchema = z.object({ zoneId: z.string(), trafficFilter: z.unknown().optional() });

/** A traffic list's or IP filter's items as address strings; undefined for an item it can't read. */
function addressesOf(
  items: Array<{ type: string; value?: unknown; start?: unknown; stop?: unknown }>,
) {
  return items.map((item) => {
    if ((item.type === 'IP_ADDRESS' || item.type === 'SUBNET') && typeof item.value === 'string')
      return item.value;
    if (
      item.type === 'IP_ADDRESS_RANGE' &&
      typeof item.start === 'string' &&
      typeof item.stop === 'string'
    )
      return `${item.start}-${item.stop}`;
    return undefined;
  });
}

function placeSide(raw: unknown, label: 'source' | 'destination', ctx: FirewallContext): Placed {
  const placed: Placed = { networkIds: [], addresses: [], unplaced: [] };
  const side = sideSchema.safeParse(raw);
  if (!side.success) {
    placed.unplaced.push(`the policy's ${label}, which names no zone,`);
    return placed;
  }
  const zone = ctx.zones.find((z) => z.id === side.data.zoneId);
  if (!zone) {
    placed.unplaced.push(
      `the policy's ${label} zone ${side.data.zoneId}, which the console does not have,`,
    );
    return placed;
  }
  const wholeZone = () => {
    placed.networkIds.push(...zone.networkIds);
    return placed;
  };
  if (side.data.trafficFilter == null) return wholeZone();
  const filter = policyFilterSchema.safeParse(side.data.trafficFilter);
  if (!filter.success) return wholeZone();
  const { networkFilter, ipAddressFilter } = filter.data;

  if (filter.data.type === 'NETWORK' && networkFilter && !networkFilter.matchOpposite) {
    placed.networkIds.push(...networkFilter.networkIds);
    return placed;
  }
  if (filter.data.type !== 'IP_ADDRESS' || !ipAddressFilter || ipAddressFilter.matchOpposite) {
    // MAC, port, region, VPN, domain, app or an opposite match: somewhere in the zone.
    return wholeZone();
  }

  let items: Array<{ type: string; value?: unknown; start?: unknown; stop?: unknown }>;
  if (ipAddressFilter.type === 'TRAFFIC_MATCHING_LIST') {
    const id = ipAddressFilter.trafficMatchingListId;
    const list = ctx.trafficLists.find((l) => l.id === id);
    if (!list || list.type !== 'IPV4_ADDRESSES') {
      placed.unplaced.push(
        list
          ? `the policy's ${label} traffic matching list "${list.name}" (${list.type}),`
          : `the policy's ${label} traffic matching list ${id ?? '(none named)'}, which unifi-mcp can't find,`,
      );
      return placed;
    }
    items = list.items;
  } else if (ipAddressFilter.type === 'IP_ADDRESSES' && ipAddressFilter.items) {
    items = ipAddressFilter.items;
  } else {
    return wholeZone();
  }
  for (const [i, address] of addressesOf(items).entries()) {
    if (address === undefined) {
      placed.unplaced.push(`the policy's ${label} match ${JSON.stringify(items[i])}`);
    } else placed.addresses.push(address);
  }
  return placed;
}

/**
 * The guard target for one or more policies (an update's before and after, or
 * every policy a reorder moves): the union of what each side reaches.
 */
export function policyTarget(policies: PolicySides[], ctx: FirewallContext): PolicyTarget {
  const target: Required<PolicyTarget> = {
    kind: 'policy',
    sourceNetworkIds: [],
    destNetworkIds: [],
    sourceAddresses: [],
    destAddresses: [],
    unplaced: [],
  };
  const add = (into: string[], values: string[]) => {
    for (const v of values) if (!into.includes(v)) into.push(v);
  };
  for (const p of policies) {
    const src = placeSide(p.source, 'source', ctx);
    const dst = placeSide(p.destination, 'destination', ctx);
    add(target.sourceNetworkIds, src.networkIds);
    add(target.destNetworkIds, dst.networkIds);
    add(target.sourceAddresses, src.addresses);
    add(target.destAddresses, dst.addresses);
    add(target.unplaced, [...src.unplaced, ...dst.unplaced]);
  }
  return target;
}
