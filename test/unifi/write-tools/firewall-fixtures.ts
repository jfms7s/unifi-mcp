// The live ZBF capture, with user-defined objects added where a test needs one:
// the console has none of its own that the API can address (its 32
// user-defined policies are IPS auto-blocks without an id).
import { liveFixture } from '../../fixtures/live.js';

export const ZONES = {
  internal: '2f3e84b1-ee47-4bbe-861f-7e63ba80e1b0',
  external: 'c266752b-f8ea-4d9e-8dc9-3658eb20eb50',
  gateway: 'b775bac7-f1c0-4956-ae2b-4635a130ed12',
  dmz: '990f0147-6ad8-4bc3-b4d5-17635a4d9c1e',
  hotspot: 'd2e63b8f-895d-4976-a0cd-d4173c1f1698',
  vpn: 'e4b8a9f8-d39f-4d4c-9120-9290c6b209e2',
} as const;

export const NETS = {
  default: '50edfc66-8b84-4f92-8753-9d69a080a695',
  iot: 'f1b4fdb6-c787-4421-92bb-56d55e0ea95a',
  piCluster: '80ec407d-e455-4a87-8b26-846881ebf07f',
} as const;

/** System-defined Internal → Internal "Allow All Traffic". */
export const SYSTEM_POLICY = 'a5043bbb-c63a-46d6-8952-93577166d2ab';

export const ZBF_MESSAGE =
  'Zone-Based Firewall is not enabled on this console; turn it on in the UniFi UI (Settings → Policy Engine)';
export const WARNING = 'This can cut unifi-mcp off from the console:';

type Row = Record<string, unknown>;
interface Page {
  offset: number;
  limit: number;
  count: number;
  totalCount: number;
  data: Row[];
}

const page = (name: string) => structuredClone(liveFixture(name)) as Page;
const extend = (p: Page, rows: Row[]): Page => ({
  ...p,
  data: [...p.data, ...rows],
  count: p.data.length + rows.length,
  totalCount: p.data.length + rows.length,
});

export function userPolicy(
  id: string,
  name: string,
  source: string,
  destination: string,
  extra: Row = {},
): Row {
  return {
    id,
    enabled: true,
    name,
    index: 10000,
    action: { type: 'BLOCK' },
    source: { zoneId: source },
    destination: { zoneId: destination },
    ipProtocolScope: { ipVersion: 'IPV4_AND_IPV6' },
    loggingEnabled: false,
    metadata: { origin: 'USER_DEFINED' },
    ...extra,
  };
}

export const policies = (...rows: Row[]) => extend(page('official-firewall-policies'), rows);
export const zones = (...rows: Row[]) => extend(page('official-firewall-zones'), rows);
export const trafficLists = (...rows: Row[]) =>
  extend(page('official-traffic-matching-lists'), rows);
export const aclRules = (...rows: Row[]) => extend(page('official-acl-rules'), rows);
export const dnsPolicies = (...rows: Row[]) => extend(page('official-dns-policies'), rows);

export const ordering = (before: Array<string | null>, after: Array<string | null> = []) => ({
  orderedFirewallPolicyIds: { beforeSystemDefined: before, afterSystemDefined: after },
});

/** A copy of `row` without `keys`: what a PUT sends back of a GET. */
export function without<T extends Row>(row: T, ...keys: string[]): Row {
  return Object.fromEntries(Object.entries(row).filter(([k]) => !keys.includes(k)));
}
