import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { policyRule } from '../firewall-view.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { lookup, sameText } from '../lookup.js';
import type { FirewallPolicy } from '../official.js';
import { policyTarget } from '../policy-scope.js';
import type { Site } from '../sites.js';
import { compact } from '../shape.js';
import { partial, write, type WriteDeps } from './common.js';
import {
  assertChangeable,
  assertUserDefined,
  filterInput,
  findPolicy,
  findZone,
  loadFirewall,
  mergeUpdate,
  namesOf,
  networkIds,
  type FirewallState,
} from './firewall-common.js';
import { diff, protectedNetworkTarget, type Plain } from './objects.js';

/** GET fields the `Create or update firewall policy` schema has no place for. */
export const POLICY_READ_ONLY = ['id', 'metadata', 'index'] as const;

/** The R20 narrowing, in the README's terms. */
const ZONE_NOTE =
  "A side that is a zone alone reaches every network in it, and UniFi's Internal zone holds every LAN. So a policy on a zone holding a protected network (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default) is confirm-level unless its filters provably exclude it: a NETWORK filter naming only other networks the console has, or IPv4 addresses, ranges or subnets (directly or through an IPv4 traffic matching list) outside the protected subnets. Addresses that overlap a protected subnet are confirm-level in any zone. Anything the guard cannot place leans to confirm: an unknown zone, list or network id, an IPv6 address, an opposite match, or a MAC, port or other filter, which counts as the whole zone.";

const FILTER_HELP =
  'Official traffic filter, e.g. {type: NETWORK, networkFilter: {networkIds, matchOpposite}}, {type: IP_ADDRESS, ipAddressFilter: {type: IP_ADDRESSES, matchOpposite, items: [{type: IP_ADDRESS|SUBNET, value} | {type: IP_ADDRESS_RANGE, start, stop}]}}, {type: IP_ADDRESS, ipAddressFilter: {type: TRAFFIC_MATCHING_LIST, matchOpposite, trafficMatchingListId}}, or PORT, MAC_ADDRESS, REGION, DOMAIN, APPLICATION...; absent means the whole zone';

const sideInput = z.object({
  zone: z.string().min(1).describe('Zone name or id'),
  trafficFilter: filterInput.optional().describe(FILTER_HELP),
});
const sidePatch = z.object({
  zone: z.string().min(1).optional().describe('Zone name or id'),
  trafficFilter: filterInput.nullable().optional().describe(`${FILTER_HELP}; null removes it`),
});

const policyFields = {
  name: z.string().min(1).describe('Policy name'),
  description: z.string().describe('Description'),
  enabled: z.boolean().describe('Whether the policy is active'),
  action: z.enum(['ALLOW', 'BLOCK', 'REJECT']).describe('What matched traffic gets'),
  allowReturnTraffic: z
    .boolean()
    .describe('ALLOW only: also allow the return traffic (default false)'),
  ipVersion: z.enum(['IPV4', 'IPV6', 'IPV4_AND_IPV6']).describe('IP versions matched'),
  connectionStateFilter: z
    .array(z.enum(['NEW', 'INVALID', 'ESTABLISHED', 'RELATED']))
    .min(1)
    .describe('Connection states matched (absent: all)'),
  ipsecFilter: z.enum(['MATCH_ENCRYPTED', 'MATCH_NOT_ENCRYPTED']).describe('IPsec match'),
  loggingEnabled: z.boolean().describe('Send matches to syslog'),
};
const nullable = {
  protocolFilter: filterInput.describe(
    'Official protocol filter, e.g. {type: NAMED_PROTOCOL, protocol: {name: TCP}, matchOpposite: false} or {type: PRESET, preset: {name: TCP_UDP}}',
  ),
  schedule: filterInput.describe('Official schedule, e.g. {mode: EVERY_DAY, ...}; absent: always'),
};

const policyInput = z.string().min(1).describe('Policy id or exact name');

const RETURN_TRAFFIC_ALLOW_ONLY =
  'allowReturnTraffic applies to ALLOW policies only; leave it out for BLOCK and REJECT';

function actionOf(type: string, allowReturnTraffic: boolean | undefined): Plain {
  return type === 'ALLOW' ? { type, allowReturnTraffic: allowReturnTraffic ?? false } : { type };
}

/** The tool input as the official `Create or update firewall policy` body. */
function createBody(
  a: {
    name: string;
    description?: string;
    enabled: boolean;
    action: string;
    allowReturnTraffic?: boolean;
    source: z.infer<typeof sideInput>;
    destination: z.infer<typeof sideInput>;
    ipVersion: string;
    protocolFilter?: Plain;
    connectionStateFilter?: string[];
    ipsecFilter?: string;
    loggingEnabled: boolean;
    schedule?: Plain;
  },
  state: FirewallState,
): Plain {
  if (a.action !== 'ALLOW' && a.allowReturnTraffic !== undefined) {
    throw new Error(RETURN_TRAFFIC_ALLOW_ONLY);
  }
  const side = (s: z.infer<typeof sideInput>) =>
    compact({ zoneId: findZone(state.zones, s.zone).id, trafficFilter: s.trafficFilter });
  return compact({
    name: a.name,
    description: a.description,
    enabled: a.enabled,
    action: actionOf(a.action, a.allowReturnTraffic),
    source: side(a.source),
    destination: side(a.destination),
    ipProtocolScope: compact({ ipVersion: a.ipVersion, protocolFilter: a.protocolFilter }),
    connectionStateFilter: a.connectionStateFilter,
    ipsecFilter: a.ipsecFilter,
    loggingEnabled: a.loggingEnabled,
    schedule: a.schedule,
  });
}

const asPolicy = (body: Plain) => body as unknown as FirewallPolicy;

export function createFirewallWriteTools(deps: WriteDeps): ToolDefinition[] {
  const resolve = async (wanted: string | undefined) => {
    const site = await deps.sites.resolve(wanted);
    return { site, state: await loadFirewall(deps, site) };
  };

  return [
    defineTool({
      name: 'unifi_create_firewall_policy',
      description: `Create a zone-based firewall policy (official POST /firewall/policies), zones by name. Easy unless it can reach a protected network; then it needs confirm: true and previews first. ${ZONE_NOTE}`,
      inputSchema: {
        site: siteInput,
        ...partial({ ...policyFields, ...nullable }),
        name: policyFields.name,
        action: policyFields.action,
        source: sideInput.describe('Where the traffic comes from'),
        destination: sideInput.describe('Where the traffic goes'),
        enabled: policyFields.enabled.default(true),
        ipVersion: policyFields.ipVersion.default('IPV4_AND_IPV6'),
        loggingEnabled: policyFields.loggingEnabled.default(false),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: false }),
      handler: async ({ site: wanted, confirm, ...a }) => {
        const { site, state } = await resolve(wanted);
        const body = createBody(a, state);
        const rule = policyRule(asPolicy(body), namesOf(state));
        return guarded(
          {
            level: 'easy',
            target: policyTarget([body], state),
            confirm,
            preview: async () => ({ would: 'create firewall policy', rule, policy: body }),
            run: async () => {
              const id = await deps.official.createFirewallObject(site.id, 'policy', body);
              return { changed: 'created', policy: { id, name: a.name, rule } };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_update_firewall_policy',
      description: `Change fields of a user-defined firewall policy. Give only what changes; source/destination merge (a null trafficFilter removes it). The tool reads the policy, merges and PUTs the whole object. Always needs confirm: true; without it the tool previews the changed fields. System-defined policies and the IPS auto-blocks are refused: UniFi manages them. ${ZONE_NOTE}`,
      inputSchema: {
        site: siteInput,
        policy: policyInput,
        ...partial(policyFields),
        protocolFilter: nullable.protocolFilter.nullable().optional(),
        schedule: nullable.schedule.nullable().optional(),
        source: sidePatch.optional(),
        destination: sidePatch.optional(),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, policy, confirm, ...a }) => {
        const { site, state } = await resolve(wanted);
        const p = findPolicy(state, policy);
        if ('ambiguous' in p) return p;
        const current = await deps.official.getFirewallObject(site.id, 'policy', p.id);
        const side = (s: z.infer<typeof sidePatch> | undefined) =>
          s === undefined
            ? undefined
            : compact({
                zoneId: s.zone === undefined ? undefined : findZone(state.zones, s.zone).id,
                trafficFilter: s.trafficFilter,
              });
        const currentAction = (current.action ?? {}) as Plain;
        const nextAction = a.action ?? (currentAction.type as string | undefined);
        if (nextAction !== 'ALLOW' && a.allowReturnTraffic !== undefined) {
          throw new Error(RETURN_TRAFFIC_ALLOW_ONLY);
        }
        const patch = compact({
          name: a.name,
          description: a.description,
          enabled: a.enabled,
          action:
            a.action !== undefined
              ? actionOf(
                  a.action,
                  a.allowReturnTraffic ?? (currentAction.allowReturnTraffic as boolean | undefined),
                )
              : a.allowReturnTraffic === undefined
                ? undefined
                : { allowReturnTraffic: a.allowReturnTraffic },
          source: side(a.source),
          destination: side(a.destination),
          ipProtocolScope:
            a.ipVersion === undefined && a.protocolFilter === undefined
              ? undefined
              : compact({ ipVersion: a.ipVersion, protocolFilter: a.protocolFilter }),
          connectionStateFilter: a.connectionStateFilter,
          ipsecFilter: a.ipsecFilter,
          loggingEnabled: a.loggingEnabled,
          schedule: a.schedule,
        }) as Plain;
        const { body, changes } = mergeUpdate(current, patch, POLICY_READ_ONLY);
        const fields = Object.keys(changes);
        if (fields.length === 0) return { unchanged: true, policy: p.name };
        return guarded(
          {
            level: 'confirm',
            target: policyTarget([p, body], state),
            confirm,
            preview: async () => ({ would: 'update firewall policy', policy: p.name, changes }),
            run: async () => {
              await deps.official.updateFirewallObject(site.id, 'policy', p.id, body);
              return { changed: 'updated', policy: p.name, fields };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_set_firewall_policy_enabled',
      description: `Enable or disable a user-defined firewall policy. Easy unless the policy can reach a protected network; then it needs confirm: true and previews first. System-defined policies and the IPS auto-blocks are refused. ${ZONE_NOTE}`,
      inputSchema: {
        site: siteInput,
        policy: policyInput,
        enabled: z.boolean().describe('true enables, false disables'),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, policy, enabled, confirm }) => {
        const { site, state } = await resolve(wanted);
        const p = findPolicy(state, policy);
        if ('ambiguous' in p) return p;
        if (p.enabled === enabled) return { unchanged: true, policy: p.name, enabled };
        const rule = policyRule({ ...p, enabled }, namesOf(state));
        const verb = enabled ? 'enable' : 'disable';
        return guarded(
          {
            level: 'easy',
            target: policyTarget([p], state),
            confirm,
            preview: async () => ({ would: `${verb} firewall policy`, policy: p.name, rule }),
            run: async () => {
              const current = await deps.official.getFirewallObject(site.id, 'policy', p.id);
              const { body } = mergeUpdate(current, { enabled }, POLICY_READ_ONLY);
              await deps.official.updateFirewallObject(site.id, 'policy', p.id, body);
              return { changed: `${verb}d`, policy: p.name, rule };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_delete_firewall_policy',
      description:
        'Delete a user-defined firewall policy (official DELETE). Always needs confirm: true; without it the tool previews. System-defined policies and the IPS auto-blocks are refused.',
      inputSchema: { site: siteInput, policy: policyInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, policy, confirm }) => {
        const { site, state } = await resolve(wanted);
        const p = findPolicy(state, policy);
        if ('ambiguous' in p) return p;
        const rule = policyRule(p, namesOf(state));
        return guarded(
          {
            level: 'confirm',
            target: policyTarget([p], state),
            confirm,
            preview: async () => ({ would: 'delete firewall policy', policy: p.name, rule }),
            run: async () => {
              await deps.official.deleteFirewallObject(site.id, 'policy', p.id);
              return { changed: 'deleted', policy: p.name, rule };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_reorder_firewall_policies',
      description:
        "Set the order of a zone pair's user-defined policies (official PUT /firewall/policies/ordering). Name every user-defined policy of the pair exactly once, by id or name, in beforeSystemDefined or afterSystemDefined. Always needs confirm: true; without it the tool previews the order before → after. System-defined policies can't be moved, and a pair holding IPS auto-blocks (no id in the API) can't be reordered here.",
      inputSchema: {
        site: siteInput,
        sourceZone: z.string().min(1).describe('Source zone name or id'),
        destinationZone: z.string().min(1).describe('Destination zone name or id'),
        beforeSystemDefined: z
          .array(z.string().min(1))
          .describe('Policies evaluated before the system-defined ones, in order'),
        afterSystemDefined: z
          .array(z.string().min(1))
          .default([])
          .describe('Policies evaluated after the system-defined ones, in order'),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, sourceZone, destinationZone, confirm, ...wantedOrder }) => {
        const { site, state } = await resolve(wanted);
        const names = namesOf(state);
        const src = findZone(state.zones, sourceZone);
        const dst = findZone(state.zones, destinationZone);
        const pairLabel = `${src.name} → ${dst.name}`;
        const inPair = state.policies.filter(
          (p) => p.source.zoneId === src.id && p.destination.zoneId === dst.id,
        );
        const resolveOne = (query: string): string => {
          const match = lookup(inPair, query, [
            (p, q) => sameText(p.id, q),
            (p, q) => sameText(p.name, q),
          ]);
          if ('none' in match) throw new Error(`"${query}" is not a policy of ${pairLabel}`);
          if ('ambiguous' in match) {
            throw new Error(
              `"${query}" matches ${match.ambiguous.length} policies of ${pairLabel}; use their ids`,
            );
          }
          assertChangeable(match.found, names);
          return match.found.id;
        };
        const next = {
          beforeSystemDefined: wantedOrder.beforeSystemDefined.map(resolveOne),
          afterSystemDefined: wantedOrder.afterSystemDefined.map(resolveOne),
        };
        const current = (
          await deps.official.firewallOrdering(site.id, {
            sourceZoneId: src.id,
            destinationZoneId: dst.id,
          })
        ).orderedFirewallPolicyIds;
        const currentIds = [...current.beforeSystemDefined, ...current.afterSystemDefined];
        const nameless = currentIds.filter((id) => id === null).length;
        if (nameless > 0) {
          throw new Error(
            `${pairLabel} can't be reordered through the API: ${nameless} of its user-defined policies have no id (IPS auto-blocks)`,
          );
        }
        const nameOf = (id: string | null) =>
          state.policies.find((p) => p.id === id)?.name ?? String(id);
        const all = [...next.beforeSystemDefined, ...next.afterSystemDefined];
        const twice = all.find((id, i) => all.indexOf(id) !== i);
        if (twice) throw new Error(`${nameOf(twice)} is named twice`);
        const missing = currentIds.filter((id) => !all.includes(id as string));
        if (missing.length) {
          throw new Error(`the new order leaves out ${missing.map(nameOf).join(', ')}`);
        }
        const extra = all.find((id) => !currentIds.includes(id));
        if (extra) {
          throw new Error(
            `${nameOf(extra)} is not in the console's user-defined order for ${pairLabel}`,
          );
        }
        const named = (o: {
          beforeSystemDefined: Array<string | null>;
          afterSystemDefined: Array<string | null>;
        }) => ({
          beforeSystemDefined: o.beforeSystemDefined.map(nameOf),
          afterSystemDefined: o.afterSystemDefined.map(nameOf),
        });
        if (Object.keys(diff(current as unknown as Plain, next as unknown as Plain)).length === 0) {
          return { unchanged: true, zones: pairLabel, order: named(next) };
        }
        return guarded(
          {
            level: 'confirm',
            target: policyTarget(
              [{ source: { zoneId: src.id }, destination: { zoneId: dst.id } }],
              state,
            ),
            confirm,
            preview: async () => ({
              would: 'reorder firewall policies',
              zones: pairLabel,
              before: named(current),
              after: named(next),
            }),
            run: async () => {
              await deps.official.reorderFirewallPolicies(
                site.id,
                { sourceZoneId: src.id, destinationZoneId: dst.id },
                next,
              );
              return { changed: 'reordered', zones: pairLabel, order: named(next) };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    ...createZoneTools(deps, resolve),
  ];
}

const zoneInput = z.string().min(1).describe('Zone name or id');
const networksInput = z
  .array(z.string().min(1))
  .describe('Networks (names or ids) in the zone; a network can be in one zone only');

function createZoneTools(
  deps: WriteDeps,
  resolve: (wanted: string | undefined) => Promise<{ site: Site; state: FirewallState }>,
): ToolDefinition[] {
  const PROTECTED_NOTE =
    'Moving a protected network (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default) into or out of a zone changes which policies reach it, so it needs confirm: true.';
  const findCustom = (state: FirewallState, query: string) => {
    const zone = findZone(state.zones, query);
    assertUserDefined('zone', `"${zone.name}"`, zone.metadata);
    return zone;
  };
  const netNames = (state: FirewallState, ids: string[]) =>
    ids.map((id) => state.networks.find((n) => n.id === id)?.name ?? id);

  return [
    defineTool({
      name: 'unifi_create_firewall_zone',
      description: `Create a custom firewall zone (official POST /firewall/zones), e.g. to move IoT out of Internal. Easy, unless it takes a protected network. ${PROTECTED_NOTE}`,
      inputSchema: {
        site: siteInput,
        name: z.string().min(1).describe('Zone name'),
        networks: networksInput.default([]),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: false }),
      handler: async ({ site: wanted, name, networks, confirm }) => {
        const { site, state } = await resolve(wanted);
        const ids = networkIds(state.networks, networks);
        const zone = { name, networks: netNames(state, ids) };
        return guarded(
          {
            level: 'easy',
            target: protectedNetworkTarget(ids, await deps.scope(site)),
            confirm,
            preview: async () => ({ would: 'create firewall zone', zone }),
            run: async () => {
              const id = await deps.official.createFirewallObject(site.id, 'zone', {
                name,
                networkIds: ids,
              });
              return { changed: 'created', zone: { id, ...zone } };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_update_firewall_zone',
      description: `Rename a custom firewall zone or set its networks (the whole list). Always needs confirm: true; without it the tool previews. System-defined zones are refused: UniFi manages them. ${PROTECTED_NOTE}`,
      inputSchema: {
        site: siteInput,
        zone: zoneInput,
        name: z.string().min(1).optional().describe('New name'),
        networks: networksInput.optional(),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, zone: query, name, networks, confirm }) => {
        const { site, state } = await resolve(wanted);
        const zone = findCustom(state, query);
        const before = { name: zone.name, networkIds: zone.networkIds };
        const after = {
          name: name ?? zone.name,
          networkIds:
            networks === undefined ? zone.networkIds : networkIds(state.networks, networks),
        };
        const changes = diff(
          { name: before.name, networks: netNames(state, before.networkIds) },
          { name: after.name, networks: netNames(state, after.networkIds) },
        );
        if (Object.keys(changes).length === 0) return { unchanged: true, zone: zone.name };
        const moved = [
          ...before.networkIds.filter((id) => !after.networkIds.includes(id)),
          ...after.networkIds.filter((id) => !before.networkIds.includes(id)),
        ];
        return guarded(
          {
            level: 'confirm',
            target: protectedNetworkTarget(moved, await deps.scope(site)),
            confirm,
            preview: async () => ({ would: 'update firewall zone', zone: zone.name, changes }),
            run: async () => {
              await deps.official.updateFirewallObject(site.id, 'zone', zone.id, after);
              return { changed: 'updated', zone: after.name, fields: Object.keys(changes) };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_delete_firewall_zone',
      description: `Delete a custom firewall zone (official DELETE). Always needs confirm: true; without it the tool previews. System-defined zones are refused. ${PROTECTED_NOTE}`,
      inputSchema: { site: siteInput, zone: zoneInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, zone: query, confirm }) => {
        const { site, state } = await resolve(wanted);
        const zone = findCustom(state, query);
        return guarded(
          {
            level: 'confirm',
            target: protectedNetworkTarget(zone.networkIds, await deps.scope(site)),
            confirm,
            preview: async () => ({
              would: 'delete firewall zone',
              zone: zone.name,
              networks: netNames(state, zone.networkIds),
            }),
            run: async () => {
              await deps.official.deleteFirewallObject(site.id, 'zone', zone.id);
              return { changed: 'deleted', zone: zone.name };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
  ];
}
