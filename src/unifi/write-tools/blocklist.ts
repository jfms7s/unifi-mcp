// unifi_block_ip / unifi_unblock_ip: one IPv4 traffic matching list and two
// BLOCK policies that match on it, found by name. The first block creates
// whatever is missing (confirm once); after that a block or unblock is one
// update of the list. An address inside a protected subnet is confirm-level.

import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
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

interface Blocklist {
  list?: TrafficList;
  inbound?: FirewallPolicy & { id: string };
  outbound?: FirewallPolicy & { id: string };
  external: string;
  internal: string;
}

function findBlocklist(state: FirewallState): Blocklist {
  const list = state.trafficLists.find((l) => l.name === BLOCKLIST);
  if (list && list.type !== 'IPV4_ADDRESSES') {
    throw new Error(
      `"${BLOCKLIST}" exists but holds ${list.type}, not IPv4 addresses; rename or delete it`,
    );
  }
  const policy = (name: string) =>
    state.policies.find(
      (p): p is FirewallPolicy & { id: string } => p.name === name && p.id !== undefined,
    );
  return {
    list,
    inbound: policy(INBOUND),
    outbound: policy(OUTBOUND),
    external: findZone(state.zones, 'External').id,
    internal: findZone(state.zones, 'Internal').id,
  };
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
      description: `Block an IPv4 address or CIDR in both directions: adds it to the IPv4 traffic matching list "${BLOCKLIST}", which "${INBOUND}" (External → Internal) and "${OUTBOUND}" (Internal → External) BLOCK. The first call creates whichever of the three is missing and needs confirm: true once (it previews the creates). After that a block is easy, unless the address is inside a protected network (pi-cluster 192.168.0.0/24), which needs confirm. An address already listed is a no-op.`,
      inputSchema: { site: siteInput, ip: ipInput, reason: reasonInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, ip, reason, confirm }) => {
        const { site, state, b } = await resolve(wanted);
        const listed = b.list?.items.some((i) => i.value === ip) ?? false;
        const complete =
          b.list !== undefined && b.inbound !== undefined && b.outbound !== undefined;
        if (complete && listed) {
          return { unchanged: true, ip, note: `${ip} is already in the ${BLOCKLIST}` };
        }
        const target = { kind: 'ip' as const, ip };
        const scope = await deps.scope();

        if (complete) {
          const list = b.list!;
          const items = [...list.items, itemFor(ip)];
          return guarded(
            {
              level: 'easy',
              target,
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
            target,
            confirm,
            preview: async () =>
              compact({ would: `create the ${BLOCKLIST}, then block ${ip}`, reason, create }),
            run: async () => {
              const created: string[] = [];
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
      description: `Remove an IPv4 address or CIDR from the "${BLOCKLIST}" (one update of the list). Easy, unless the address is inside a protected network. The console can't hold an empty list, so removing the last address deletes the blocklist (both policies, then the list) and needs confirm: true; the next unifi_block_ip recreates it. An address not listed is a no-op.`,
      inputSchema: { site: siteInput, ip: ipInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, ip, confirm }) => {
        const { site, b } = await resolve(wanted);
        const list = b.list;
        if (!list || !list.items.some((i) => i.value === ip)) {
          return { unchanged: true, ip, note: `${ip} is not in the ${BLOCKLIST}` };
        }
        const remaining = list.items.filter((i) => i.value !== ip);
        const target = { kind: 'ip' as const, ip };
        const scope = await deps.scope();
        if (remaining.length > 0) {
          return guarded(
            {
              level: 'easy',
              target,
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
            target,
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
