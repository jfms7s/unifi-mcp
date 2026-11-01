// Placing a zone policy for the guard (R14, R19): which networks and
// addresses each side can match, built from the live ZBF capture, where the
// Internal zone holds Default, IoT and pi-cluster.
import { beforeAll, describe, expect, it } from 'vitest';
import {
  loadProtectedScope,
  touchesProtected,
  type ProtectedScope,
} from '../../src/unifi/guard.js';
import type { FirewallZone, TrafficList } from '../../src/unifi/official.js';
import { policyTarget, type FirewallContext } from '../../src/unifi/policy-scope.js';
import { liveFixture } from '../fixtures/live.js';
import { readDeps } from './fixtures.js';

const INTERNAL = '2f3e84b1-ee47-4bbe-861f-7e63ba80e1b0';
const EXTERNAL = 'c266752b-f8ea-4d9e-8dc9-3658eb20eb50';
const GATEWAY_ZONE = 'b775bac7-f1c0-4956-ae2b-4635a130ed12';
const DMZ = '990f0147-6ad8-4bc3-b4d5-17635a4d9c1e';
const PI_CLUSTER = '80ec407d-e455-4a87-8b26-846881ebf07f';
const DEFAULT_NET = '50edfc66-8b84-4f92-8753-9d69a080a695';
const IOT = 'f1b4fdb6-c787-4421-92bb-56d55e0ea95a';
const WAN1 = '984ca476-c888-45ec-b042-a67b1991ed98';

const zones = (liveFixture('official-firewall-zones') as { data: FirewallZone[] }).data;
const list = (id: string, items: TrafficList['items'], type = 'IPV4_ADDRESSES'): TrafficList => ({
  id,
  name: `list ${id}`,
  type,
  items,
});
const ctx = (trafficLists: TrafficList[] = []): FirewallContext => ({ zones, trafficLists });

const ips = (...values: string[]) => ({
  type: 'IP_ADDRESS',
  ipAddressFilter: {
    type: 'IP_ADDRESSES',
    matchOpposite: false,
    items: values.map((v) =>
      v.includes('-')
        ? { type: 'IP_ADDRESS_RANGE', start: v.split('-')[0], stop: v.split('-')[1] }
        : { type: v.includes('/') ? 'SUBNET' : 'IP_ADDRESS', value: v },
    ),
  },
});
const viaList = (id: string, matchOpposite = false) => ({
  type: 'IP_ADDRESS',
  ipAddressFilter: { type: 'TRAFFIC_MATCHING_LIST', matchOpposite, trafficMatchingListId: id },
});
const nets = (...networkIds: string[]) => ({
  type: 'NETWORK',
  networkFilter: { matchOpposite: false, networkIds },
});

let scope: ProtectedScope;
beforeAll(async () => {
  const deps = readDeps();
  scope = await loadProtectedScope(['pi-cluster'], deps, await deps.sites.resolve());
});

const reason = (policy: { source?: unknown; destination?: unknown }, c = ctx()) =>
  touchesProtected(policyTarget([policy], c), scope, []);

describe('policyTarget', () => {
  it('a zone-only side expands into the zone networks (R14)', () => {
    expect(
      policyTarget([{ source: { zoneId: INTERNAL }, destination: { zoneId: EXTERNAL } }], ctx()),
    ).toEqual({
      kind: 'policy',
      sourceNetworkIds: [DEFAULT_NET, IOT, PI_CLUSTER],
      destNetworkIds: [WAN1, '71e7ee20-439e-4eb7-822a-4d801cb23c14'],
      sourceAddresses: [],
      destAddresses: [],
      unplaced: [],
    });
  });

  it('a NETWORK filter narrows the side to those networks', () => {
    const t = policyTarget(
      [
        {
          source: { zoneId: INTERNAL, trafficFilter: nets(IOT) },
          destination: { zoneId: EXTERNAL },
        },
      ],
      ctx(),
    );
    expect(t.sourceNetworkIds).toEqual([IOT]);
  });

  it('an IP filter places the side by its addresses, ranges and subnets', () => {
    const t = policyTarget(
      [
        {
          source: { zoneId: INTERNAL, trafficFilter: ips('192.168.10.5', '192.168.11.0/24') },
          destination: { zoneId: EXTERNAL, trafficFilter: ips('198.51.100.1-198.51.100.9') },
        },
      ],
      ctx(),
    );
    expect(t.sourceNetworkIds).toEqual([]);
    expect(t.sourceAddresses).toEqual(['192.168.10.5', '192.168.11.0/24']);
    expect(t.destAddresses).toEqual(['198.51.100.1-198.51.100.9']);
  });

  it('a traffic matching list contributes its items', () => {
    const t = policyTarget(
      [
        {
          source: { zoneId: EXTERNAL, trafficFilter: viaList('l1') },
          destination: { zoneId: INTERNAL },
        },
      ],
      ctx([
        list('l1', [
          { type: 'IP_ADDRESS', value: '203.0.113.9' },
          { type: 'SUBNET', value: '192.168.0.0/28' },
        ]),
      ]),
    );
    expect(t.sourceAddresses).toEqual(['203.0.113.9', '192.168.0.0/28']);
  });

  it('several policies (an update before and after) are one target', () => {
    const t = policyTarget(
      [
        { source: { zoneId: EXTERNAL }, destination: { zoneId: DMZ } },
        {
          source: { zoneId: EXTERNAL },
          destination: { zoneId: INTERNAL, trafficFilter: nets(IOT) },
        },
      ],
      ctx(),
    );
    expect(t.destNetworkIds).toEqual([IOT]);
  });
});

describe('a policy touches pi-cluster', () => {
  it('when a side is the Internal zone alone (R19), even BLOCK Internal → External', () => {
    expect(reason({ source: { zoneId: INTERNAL }, destination: { zoneId: EXTERNAL } })).toBe(
      "the policy's source includes pi-cluster, a protected network",
    );
    expect(reason({ source: { zoneId: EXTERNAL }, destination: { zoneId: INTERNAL } })).toContain(
      'destination includes pi-cluster',
    );
  });

  it('when a NETWORK filter names it', () => {
    expect(
      reason({
        source: { zoneId: INTERNAL, trafficFilter: nets(PI_CLUSTER) },
        destination: { zoneId: GATEWAY_ZONE },
      }),
    ).toContain('source includes pi-cluster');
  });

  it('when an address, range or subnet overlaps 192.168.0.0/24', () => {
    for (const filter of [
      ips('192.168.0.17'),
      ips('192.168.0.0/16'),
      ips('192.167.255.250-192.168.0.3'),
    ]) {
      expect(
        reason({
          source: { zoneId: EXTERNAL },
          destination: { zoneId: INTERNAL, trafficFilter: filter },
        }),
        JSON.stringify(filter),
      ).toMatch(/destination matches .* inside pi-cluster \(192\.168\.0\.0\/24\)/);
    }
  });

  it('when a traffic matching list holds a pi-cluster address', () => {
    const lists = [list('l1', [{ type: 'IP_ADDRESS', value: '192.168.0.40' }])];
    expect(
      reason(
        {
          source: { zoneId: EXTERNAL, trafficFilter: viaList('l1') },
          destination: { zoneId: DMZ },
        },
        ctx(lists),
      ),
    ).toContain('192.168.0.40');
  });

  it('not when every side is placed outside it', () => {
    expect(
      reason({
        source: { zoneId: INTERNAL, trafficFilter: ips('192.168.10.5') },
        destination: { zoneId: EXTERNAL },
      }),
    ).toBeUndefined();
    expect(
      reason({
        source: { zoneId: INTERNAL, trafficFilter: nets(IOT) },
        destination: { zoneId: INTERNAL, trafficFilter: nets(DEFAULT_NET) },
      }),
    ).toBeUndefined();
    expect(reason({ source: { zoneId: EXTERNAL }, destination: { zoneId: DMZ } })).toBeUndefined();
  });
});

describe('what it cannot place leans to confirm', () => {
  const can = (r: string | undefined) => expect(r).toMatch(/can't place/);

  it('a zone the console does not have', () => {
    can(reason({ source: { zoneId: 'nope' }, destination: { zoneId: EXTERNAL } }));
  });

  it('a side with no zone at all', () => {
    can(reason({ source: {}, destination: { zoneId: EXTERNAL } }));
    can(reason({ destination: { zoneId: EXTERNAL } }));
  });

  it('a traffic matching list it cannot find, or one that is not IPv4 addresses', () => {
    can(
      reason({
        source: { zoneId: EXTERNAL, trafficFilter: viaList('gone') },
        destination: { zoneId: DMZ },
      }),
    );
    can(
      reason(
        {
          source: { zoneId: EXTERNAL, trafficFilter: viaList('v6') },
          destination: { zoneId: DMZ },
        },
        ctx([list('v6', [{ type: 'SUBNET', value: '2001:db8::/32' }], 'IPV6_ADDRESSES')]),
      ),
    );
  });

  it('an IPv6 address or an item it does not know', () => {
    can(
      reason({
        source: { zoneId: EXTERNAL, trafficFilter: ips('2001:db8::1') },
        destination: { zoneId: DMZ },
      }),
    );
    const odd = {
      type: 'IP_ADDRESS',
      ipAddressFilter: { type: 'IP_ADDRESSES', items: [{ type: 'WILDCARD' }] },
    };
    can(reason({ source: { zoneId: EXTERNAL, trafficFilter: odd }, destination: { zoneId: DMZ } }));
  });

  it('matchOpposite, a MAC, port or unknown filter, or a malformed one, falls back to the whole zone', () => {
    const opposite = {
      ...ips('192.168.10.5'),
      ipAddressFilter: { ...ips('192.168.10.5').ipAddressFilter, matchOpposite: true },
    };
    for (const trafficFilter of [
      opposite,
      viaList('l1', true),
      { ...nets(IOT), networkFilter: { matchOpposite: true, networkIds: [IOT] } },
      { type: 'MAC_ADDRESS', macAddressFilter: { macAddresses: ['02:00:00:00:00:01'] } },
      { type: 'PORT', portFilter: { type: 'PORTS', matchOpposite: false, items: [] } },
      { type: 'SOMETHING_NEW' },
      { type: 'IP_ADDRESS' },
      'garbage',
    ]) {
      expect(
        reason(
          { source: { zoneId: INTERNAL, trafficFilter }, destination: { zoneId: EXTERNAL } },
          ctx([list('l1', [])]),
        ),
        JSON.stringify(trafficFilter),
      ).toContain('pi-cluster');
    }
  });

  it('with nothing protected, nothing is unplaceable', () => {
    const empty = { ...scope, networkIds: new Set<string>(), subnets: [], networkNames: new Map() };
    expect(
      touchesProtected(
        policyTarget([{ source: { zoneId: 'nope' }, destination: { zoneId: INTERNAL } }], ctx()),
        empty,
        [],
      ),
    ).toBeUndefined();
  });
});
