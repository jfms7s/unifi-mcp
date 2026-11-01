// unifi_block_ip / unifi_unblock_ip: one IPv4 traffic matching list and two
// BLOCK policies that match on it, found by name. The first block creates
// whatever is missing (confirm once); after that a block or unblock is one
// update of the list. An address inside a protected subnet is confirm-level.

import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { describeError } from '../../http/errors.js';
import { guarded, touchesProtected, type ProtectedScope } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import type { FirewallPolicy, TrafficList } from '../official.js';
import { compact } from '../shape.js';
import { write, type WriteDeps } from './common.js';
import { findZone, loadFirewall, type FirewallState } from './firewall-common.js';

export const BLOCKLIST = 'unifi-mcp blocklist';
export const INBOUND = 'unifi-mcp blocklist inbound';
export const OUTBOUND = 'unifi-mcp blocklist outbound';

const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_OR_CIDR = new RegExp(`^${OCTET}(\\.${OCTET}){3}(/(3[0-2]|[12]?\\d))?$`);

const ipInput = z
  .string()
  .regex(IPV4_OR_CIDR, 'an IPv4 address (203.0.113.7) or CIDR (203.0.113.0/24)')
  .describe('IPv4 address or CIDR');
const reasonInput = z
  .string()
  .max(200)
  .optional()
  .describe('Why (echoed back; traffic matching lists have no place to keep it)');

const itemFor = (ip: string) => ({ type: ip.includes('/') ? 'SUBNET' : 'IP_ADDRESS', value: ip });

/**
 * One spelling per member: `x/32` is `x`, and a CIDR's host bits are zeroed
 * (203.0.113.9/24 is 203.0.113.0/24), so a member is found however it is
 * written. A value that is not IPv4 is kept as it is.
 */
export function canonicalIp(value: string): string {
  if (!IPV4_OR_CIDR.test(value)) return value;
  const [address = '', bits] = value.split('/');
  const prefix = bits === undefined ? 32 : Number(bits);
  if (prefix === 32) return address;
  const n = address.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
  const network = prefix === 0 ? 0 : Math.floor(n / 2 ** (32 - prefix)) * 2 ** (32 - prefix);
  const octets = [24, 16, 8, 0].map((shift) => Math.floor(network / 2 ** shift) % 256);
  return `${octets.join('.')}/${prefix}`;
}

const sameMember = (item: { value?: unknown }, ip: string) =>
  typeof item.value === 'string' && canonicalIp(item.value) === ip;

interface Blocklist {
  list?: TrafficList;
  inbound?: FirewallPolicy & { id: string };
  outbound?: FirewallPolicy & { id: string };
  external: string;
  internal: string;
}

const FIX = 'rename or delete it in the UniFi app';

/**
 * A blocklist policy is trusted only when it is wired as unifi-mcp makes it:
 * BLOCK, on its zone pair, matching the blocklist (not its opposite) on the
 * expected side. A policy that only has the name is refused, never used or
 * deleted.
 */
function checkPolicy(
  p: FirewallPolicy,
  direction: 'inbound' | 'outbound',
  list: TrafficList,
  zones: { external: string; internal: string; names: [string, string] },
): asserts p is FirewallPolicy & { id: string } {
  const label = `"${p.name}"`;
  const inbound = direction === 'inbound';
  if (p.id === undefined) throw new Error(`${label} has no id in the official API; ${FIX}`);
  if (p.action.type !== 'BLOCK') throw new Error(`${label} is not a BLOCK policy; ${FIX}`);
  const [from, to] = inbound ? [zones.external, zones.internal] : [zones.internal, zones.external];
  if (p.source.zoneId !== from || p.destination.zoneId !== to) {
    const [ext, int] = zones.names;
    throw new Error(`${label} is not ${inbound ? `${ext} → ${int}` : `${int} → ${ext}`}; ${FIX}`);
  }
  const side = inbound ? p.source : p.destination;
  const f = side.trafficFilter;
  const a = f?.ipAddressFilter;
  const wired =
    f?.type === 'IP_ADDRESS' &&
    a?.type === 'TRAFFIC_MATCHING_LIST' &&
    !a.matchOpposite &&
    a.trafficMatchingListId === list.id;
  if (!wired) {
    throw new Error(
      `${label} does not match on the "${BLOCKLIST}" in its ${inbound ? 'source' : 'destination'}; ${FIX}`,
    );
  }
}

function findBlocklist(state: FirewallState): Blocklist {
  const lists = state.trafficLists.filter((l) => l.name === BLOCKLIST);
  if (lists.length > 1) throw new Error(`${lists.length} lists are named "${BLOCKLIST}"; ${FIX}`);
  const list = lists[0];
  if (list && list.type !== 'IPV4_ADDRESSES') {
    throw new Error(`"${BLOCKLIST}" exists but holds ${list.type}, not IPv4 addresses; ${FIX}`);
  }
  const external = findZone(state.zones, 'External');
  const internal = findZone(state.zones, 'Internal');
  const zones = {
    external: external.id,
    internal: internal.id,
    names: [external.name, internal.name] as [string, string],
  };
  const policy = (name: string, direction: 'inbound' | 'outbound') => {
    const named = state.policies.filter((p) => p.name === name);
    if (named.length === 0) return undefined;
    if (named.length > 1) throw new Error(`${named.length} policies are named "${name}"; ${FIX}`);
    const p = named[0]!;
    // Policies without their list would get a fresh, orphan list: refuse instead.
    if (!list) throw new Error(`"${name}" exists but the "${BLOCKLIST}" list does not; ${FIX}`);
    checkPolicy(p, direction, list, zones);
    return p;
  };
  return {
    list,
    inbound: policy(INBOUND, 'inbound'),
    outbound: policy(OUTBOUND, 'outbound'),
    external: external.id,
    internal: internal.id,
  };
}

/** Prefixes shorter than this block (or free) a large share of the address space. */
const WIDE_PREFIX = 16;

/**
 * Why a block or unblock of `ip` needs confirm: a protected address, or a
 * range wide enough to hold things nobody meant to touch.
 */
function confirmReason(ip: string, verb: 'blocks' | 'unblocks', scope: ProtectedScope) {
  const prefix = ip.includes('/') ? Number(ip.split('/')[1]) : 32;
  const wide =
    prefix < WIDE_PREFIX
      ? `${ip} ${verb} a large address range (/${prefix}), which may hold addresses unifi-mcp or its network need`
      : undefined;
  const reasons = [touchesProtected({ kind: 'ip', ip }, scope, []), wide].filter(Boolean);
  return reasons.length ? reasons.join('; ') : undefined;
}

const listFilter = (listId: string) => ({
  type: 'IP_ADDRESS',
  ipAddressFilter: {
    type: 'TRAFFIC_MATCHING_LIST',
    matchOpposite: false,
    trafficMatchingListId: listId,
  },
});

function policyBody(direction: 'inbound' | 'outbound', b: Blocklist, listId: string) {
  const inbound = direction === 'inbound';
  return {
    name: inbound ? INBOUND : OUTBOUND,
    description: `Managed by unifi-mcp: traffic ${inbound ? 'from' : 'to'} the addresses in the ${BLOCKLIST}`,
    enabled: true,
    action: { type: 'BLOCK' },
    source: inbound
      ? { zoneId: b.external, trafficFilter: listFilter(listId) }
      : { zoneId: b.internal },
    destination: inbound
      ? { zoneId: b.internal }
      : { zoneId: b.external, trafficFilter: listFilter(listId) },
    ipProtocolScope: { ipVersion: 'IPV4' },
    loggingEnabled: false,
  };
}

/** The list's PUT body: what the console holds, with these items. */
const listBody = (list: TrafficList, items: TrafficList['items']) => ({
  name: list.name,
  type: list.type,
  items,
});

/** Disabled blocklist policies, said plainly: the IP is listed but not blocked that way. */
function disabledNote(b: Blocklist): string | undefined {
  const off = [b.inbound, b.outbound]
    .filter((p) => p && !p.enabled)
    .map((p) => `"${p!.name}" is disabled`);
  return off.length ? `${off.join('; ')}, so that direction is not blocked` : undefined;
}

export function createBlocklistWriteTools(deps: WriteDeps): ToolDefinition[] {
  const resolve = async (wanted: string | undefined) => {
    const site = await deps.sites.resolve(wanted);
    const state = await loadFirewall(deps, site);
    return { site, state, b: findBlocklist(state) };
  };

  return [
    defineTool({
      name: 'unifi_block_ip',
      description: `Block an IPv4 address or CIDR in both directions: adds it to the IPv4 traffic matching list "${BLOCKLIST}", which "${INBOUND}" (External → Internal) and "${OUTBOUND}" (Internal → External) BLOCK. The first call creates whichever of the three is missing and needs confirm: true once (it previews the creates). After that a block is easy, unless it overlaps a protected network's subnet (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default) or is a wide range (a prefix shorter than /16); those need confirm. An address already listed (x and x/32 are one address) is a no-op.`,
      inputSchema: { site: siteInput, ip: ipInput, reason: reasonInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, ip: given, reason, confirm }) => {
        const ip = canonicalIp(given);
        const { site, state, b } = await resolve(wanted);
        const listed = b.list?.items.some((i) => sameMember(i, ip)) ?? false;
        const complete =
          b.list !== undefined && b.inbound !== undefined && b.outbound !== undefined;
        if (complete && listed) {
          const off = disabledNote(b);
          return {
            unchanged: true,
            ip,
            note: `${ip} is already in the ${BLOCKLIST}${off ? `; ${off}` : ''}`,
          };
        }
        const scope = await deps.scope(site);
        const why = confirmReason(ip, 'blocks', scope);

        if (complete) {
          const list = b.list!;
          const items = [...list.items, itemFor(ip)];
          return guarded(
            {
              level: 'easy',
              reason: why,
              confirm,
              preview: async () => compact({ would: `block ${ip}`, reason, blocklist: BLOCKLIST }),
              run: async () => {
                await deps.official.updateFirewallObject(
                  site.id,
                  'traffic-list',
                  list.id,
                  listBody(list, items),
                );
                return compact({
                  changed: 'blocked',
                  ip,
                  reason,
                  blocklist: items.length,
                  note: disabledNote(b),
                });
              },
            },
            scope,
            [],
          );
        }

        const zone = (id: string) => state.zones.find((z) => z.id === id)?.name ?? id;
        const [ext, int] = [zone(b.external), zone(b.internal)];
        const create = [
          ...(b.list ? [] : [`traffic matching list "${BLOCKLIST}" (IPv4 addresses): ${ip}`]),
          ...(b.inbound
            ? []
            : [`policy "${INBOUND}": ${ext} → ${int}: BLOCK from list "${BLOCKLIST}"`]),
          ...(b.outbound
            ? []
            : [`policy "${OUTBOUND}": ${int} → ${ext}: BLOCK to list "${BLOCKLIST}"`]),
        ];
        return guarded(
          {
            level: 'confirm',
            reason: why,
            confirm,
            preview: async () =>
              compact({ would: `create the ${BLOCKLIST}, then block ${ip}`, reason, create }),
            run: async () => {
              const created: string[] = [];
              const planned = [
                ...(b.list ? [] : ['list']),
                ...(b.inbound ? [] : ['inbound']),
                ...(b.outbound ? [] : ['outbound']),
              ];
              try {
                let listId: string;
                if (b.list) {
                  listId = b.list.id;
                  if (!listed) {
                    await deps.official.updateFirewallObject(
                      site.id,
                      'traffic-list',
                      listId,
                      listBody(b.list, [...b.list.items, itemFor(ip)]),
                    );
                  }
                } else {
                  listId = await deps.official.createFirewallObject(site.id, 'traffic-list', {
                    name: BLOCKLIST,
                    type: 'IPV4_ADDRESSES',
                    items: [itemFor(ip)],
                  });
                  created.push('list');
                }
                for (const direction of ['inbound', 'outbound'] as const) {
                  if (b[direction]) continue;
                  await deps.official.createFirewallObject(
                    site.id,
                    'policy',
                    policyBody(direction, b, listId),
                  );
                  created.push(direction);
                }
              } catch (error) {
                // Say exactly what exists now, so the next call (or a person) can finish or undo it.
                const missing = planned.filter((x) => !created.includes(x));
                throw new Error(
                  `the ${BLOCKLIST} was only partly created: created ${created.join(', ') || 'nothing'}; not created ${missing.join(', ')}; ${describeError(error)}`,
                );
              }
              return compact({ changed: 'blocked', ip, reason, created, note: disabledNote(b) });
            },
          },
          scope,
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_unblock_ip',
      description: `Remove an IPv4 address or CIDR from the "${BLOCKLIST}" (one update of the list). Easy, unless it overlaps a protected network's subnet (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default) or is a wide range (a prefix shorter than /16); those need confirm. The console can't hold an empty list, so removing the last address deletes the blocklist (both policies, then the list) and needs confirm: true; the next unifi_block_ip recreates it. An address not listed is a no-op.`,
      inputSchema: { site: siteInput, ip: ipInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, ip: given, confirm }) => {
        const ip = canonicalIp(given);
        const { site, b } = await resolve(wanted);
        const list = b.list;
        if (!list || !list.items.some((i) => sameMember(i, ip))) {
          return { unchanged: true, ip, note: `${ip} is not in the ${BLOCKLIST}` };
        }
        const remaining = list.items.filter((i) => !sameMember(i, ip));
        const scope = await deps.scope(site);
        const why = confirmReason(ip, 'unblocks', scope);
        if (remaining.length > 0) {
          return guarded(
            {
              level: 'easy',
              reason: why,
              confirm,
              preview: async () => ({ would: `unblock ${ip}`, blocklist: BLOCKLIST }),
              run: async () => {
                await deps.official.updateFirewallObject(
                  site.id,
                  'traffic-list',
                  list.id,
                  listBody(list, remaining),
                );
                return { changed: 'unblocked', ip, blocklist: remaining.length };
              },
            },
            scope,
            [],
          );
        }
        const policies = [b.outbound, b.inbound].filter((p) => p !== undefined);
        return guarded(
          {
            level: 'confirm',
            reason: why,
            confirm,
            preview: async () => ({
              would: `unblock ${ip}, the last address: delete the ${BLOCKLIST} (both policies, then the list)`,
              delete: [
                ...policies.map((p) => `policy "${p.name}"`),
                `traffic matching list "${BLOCKLIST}"`,
              ],
            }),
            run: async () => {
              for (const p of policies)
                await deps.official.deleteFirewallObject(site.id, 'policy', p.id);
              await deps.official.deleteFirewallObject(site.id, 'traffic-list', list.id);
              return {
                changed: 'unblocked',
                ip,
                deleted: [...policies.map((p) => p.name), BLOCKLIST],
              };
            },
          },
          scope,
          [],
        );
      },
    }),
  ];
}
