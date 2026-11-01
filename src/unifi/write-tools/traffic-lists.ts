import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { TrafficList } from '../official.js';
import { policyTarget, type PolicyTarget } from '../policy-scope.js';
import { compact } from '../shape.js';
import { write, type WriteDeps } from './common.js';
import {
  itemAddress,
  loadFirewall,
  mergeUpdate,
  policiesUsing,
  type FirewallState,
} from './firewall-common.js';

export const LIST_READ_ONLY = ['id', 'metadata'] as const;

const itemsInput = z
  .array(z.record(z.string(), z.unknown()))
  .min(1)
  .describe(
    'Official items: IPv4/IPv6 lists take {type: IP_ADDRESS|SUBNET, value} or {type: IP_ADDRESS_RANGE, start, stop}; PORTS lists take {type: PORT_NUMBER, value} or {type: PORT_NUMBER_RANGE, start, stop}',
  );
const listInput = z.string().min(1).describe('Traffic matching list id or exact name');

/**
 * Who a change to a list can affect. For an IPv4 list, exactly the addresses
 * that enter or leave it: a host whose address the change does not touch is
 * matched as before by every policy using the list. Any other list (ports,
 * IPv6) affects whatever its policies reach.
 */
export function listChangeTarget(
  before: TrafficList['items'],
  after: TrafficList['items'],
  type: string,
  using: FirewallState['policies'],
  state: FirewallState,
): PolicyTarget {
  if (type !== 'IPV4_ADDRESSES') return policyTarget(using, state);
  const key = (i: TrafficList['items'][number]) => itemAddress(i) ?? JSON.stringify(i);
  const was = new Set(before.map(key));
  const now = new Set(after.map(key));
  const changed = [...before, ...after].filter((i) => was.has(key(i)) !== now.has(key(i)));
  return {
    kind: 'policy',
    sourceNetworkIds: [],
    destNetworkIds: [],
    sourceAddresses: [...new Set(changed.map(key))],
    destAddresses: [],
  };
}

function findList(state: FirewallState, query: string): TrafficList | ReturnType<typeof ambiguous> {
  const match = lookup(state.trafficLists, query, [
    (l, q) => sameText(l.id, q),
    (l, q) => sameText(l.name, q),
  ]);
  if ('ambiguous' in match)
    return ambiguous(query, match.ambiguous, (l: TrafficList) => ({
      id: l.id,
      name: l.name,
      type: l.type,
    }));
  if ('none' in match) {
    const names = state.trafficLists.map((l) => l.name);
    throw new Error(
      `No traffic matching list matches "${query}"; ${names.length ? `the lists are: ${names.join(', ')}` : 'the console has none'}`,
    );
  }
  return match.found;
}

const NOTE =
  "A change that adds or removes an address in a protected network's subnet (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default), or a ports/IPv6 list used by a policy that reaches one, warns in its preview.";

export function createTrafficListWriteTools(deps: WriteDeps): ToolDefinition[] {
  const resolve = async (wanted: string | undefined) => {
    const site = await deps.sites.resolve(wanted);
    return { site, state: await loadFirewall(deps, site) };
  };
  const usedBy = (state: FirewallState, list: TrafficList) => {
    const names = policiesUsing(state.policies, list.id).map((p) => p.name);
    return names.length ? names : undefined;
  };

  return [
    defineTool({
      name: 'unifi_create_traffic_list',
      description:
        'Create a traffic matching list (official POST /traffic-matching-lists) of IPv4 addresses, IPv6 addresses or ports, for firewall policies to match on. Easy: a new list is used by nothing yet.',
      inputSchema: {
        site: siteInput,
        name: z.string().min(1).describe('List name'),
        type: z.enum(['IPV4_ADDRESSES', 'IPV6_ADDRESSES', 'PORTS']).describe('What it holds'),
        items: itemsInput,
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, name, type, items }) => {
        const site = await deps.sites.resolve(wanted);
        const body = { name, type, items };
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'create traffic matching list', trafficList: body }),
            run: async () => {
              const id = await deps.official.createFirewallObject(site.id, 'traffic-list', body);
              return { changed: 'created', trafficList: { id, name, items: items.length } };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_update_traffic_list',
      description: `Rename a traffic matching list or replace its items (the whole list). Every policy using it changes with it. Always needs confirm: true; without it the tool previews the change and the policies that use the list. ${NOTE}`,
      inputSchema: {
        site: siteInput,
        trafficList: listInput,
        name: z.string().min(1).optional().describe('New name'),
        items: itemsInput.optional(),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, trafficList, name, items, confirm }) => {
        const { site, state } = await resolve(wanted);
        const list = findList(state, trafficList);
        if ('ambiguous' in list) return list;
        const current = await deps.official.getFirewallObject(site.id, 'traffic-list', list.id);
        const { body, changes } = mergeUpdate(current, compact({ name, items }), LIST_READ_ONLY);
        const fields = Object.keys(changes);
        if (fields.length === 0) return { unchanged: true, trafficList: list.name };
        const after = (body.items as TrafficList['items'] | undefined) ?? list.items;
        const using = policiesUsing(state.policies, list.id);
        return guarded(
          {
            level: 'confirm',
            target: listChangeTarget(list.items, after, list.type, using, state),
            confirm,
            preview: async () =>
              compact({
                would: 'update traffic matching list',
                trafficList: list.name,
                changes,
                usedBy: usedBy(state, list),
              }),
            run: async () => {
              await deps.official.updateFirewallObject(site.id, 'traffic-list', list.id, body);
              return { changed: 'updated', trafficList: list.name, fields };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_delete_traffic_list',
      description: `Delete a traffic matching list (official DELETE); the console refuses one still in use. Always needs confirm: true; without it the tool previews, with the policies that use it. ${NOTE}`,
      inputSchema: { site: siteInput, trafficList: listInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, trafficList, confirm }) => {
        const { site, state } = await resolve(wanted);
        const list = findList(state, trafficList);
        if ('ambiguous' in list) return list;
        const using = policiesUsing(state.policies, list.id);
        return guarded(
          {
            level: 'confirm',
            target: listChangeTarget(list.items, [], list.type, using, state),
            confirm,
            preview: async () =>
              compact({
                would: 'delete traffic matching list',
                trafficList: list.name,
                items: list.items.length,
                usedBy: usedBy(state, list),
              }),
            run: async () => {
              await deps.official.deleteFirewallObject(site.id, 'traffic-list', list.id);
              return { changed: 'deleted', trafficList: list.name };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
  ];
}
