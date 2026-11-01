import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { AclRule } from '../official.js';
import type { PolicyTarget } from '../policy-scope.js';
import { aclEndpointSchema } from '../schemas.js';
import { compact } from '../shape.js';
import type { Site } from '../sites.js';
import { partial, write, type WriteDeps } from './common.js';
import { assertUserDefined, filterInput, mergeUpdate, unionTargets } from './firewall-common.js';
import type { Plain } from './objects.js';

/** GET fields the `ACL rule update` schema has no place for (`index` is deprecated there). */
export const ACL_READ_ONLY = ['id', 'metadata', 'index'] as const;

const ENDPOINT_HELP =
  'Official ACL endpoint: {type: NETWORKS, networkIds, portFilter?}, {type: IP_ADDRESSES_OR_SUBNETS, ipAddressesOrSubnets, portFilter?} or {type: PORTS, portFilter}; absent matches any';

const aclFields = {
  name: z.string().min(1).describe('Rule name'),
  type: z.enum(['IPV4', 'MAC']).describe('IPV4 (default) or MAC'),
  action: z.enum(['ALLOW', 'BLOCK']).describe('What matched traffic gets'),
  enabled: z.boolean().describe('Whether the rule is active'),
  description: z.string().describe('Description'),
  sourceFilter: filterInput.describe(ENDPOINT_HELP),
  destinationFilter: filterInput.describe(ENDPOINT_HELP),
  protocolFilter: z
    .array(z.enum(['TCP', 'UDP']))
    .min(1)
    .describe('Protocols (absent: all)'),
  enforcingDeviceFilter: filterInput.describe('Switches that enforce it (absent: all)'),
  networkIdFilter: z.string().describe('MAC rules: the network they apply on'),
};

/**
 * Where an ACL rule reaches, as a guard target: network endpoints by network,
 * address endpoints by address. Any other endpoint (none, ports only, MACs)
 * can match any host, so it is reported as unplaced and leans to confirm.
 */
export function aclTarget(rule: Plain, knownNetworks?: Set<string>): PolicyTarget {
  const target: Required<PolicyTarget> = {
    kind: 'policy',
    sourceNetworkIds: [],
    destNetworkIds: [],
    sourceAddresses: [],
    destAddresses: [],
    unplaced: [],
  };
  for (const [label, raw, nets, addrs] of [
    ['source', rule.sourceFilter, target.sourceNetworkIds, target.sourceAddresses],
    ['destination', rule.destinationFilter, target.destNetworkIds, target.destAddresses],
  ] as const) {
    const parsed = aclEndpointSchema.safeParse(raw);
    const e = parsed.success ? parsed.data : undefined;
    if (e?.type === 'NETWORKS' && e.networkIds?.length) {
      for (const id of e.networkIds) {
        if (!knownNetworks || knownNetworks.has(id)) nets.push(id);
        else
          target.unplaced.push(
            `the ACL rule's ${label} network ${id}, which the console does not have,`,
          );
      }
    } else if (e?.type === 'IP_ADDRESSES_OR_SUBNETS' && e.ipAddressesOrSubnets?.length)
      addrs.push(...e.ipAddressesOrSubnets);
    else if (rule.type === 'MAC' && typeof rule.networkIdFilter === 'string') {
      if (!knownNetworks || knownNetworks.has(rule.networkIdFilter))
        nets.push(rule.networkIdFilter);
      else
        target.unplaced.push(
          `the ACL rule's ${label} network ${rule.networkIdFilter}, which the console does not have,`,
        );
    } else
      target.unplaced.push(
        `the ACL rule's ${label}${e ? ` (${e.type})` : ''}, which is not limited to networks or addresses,`,
      );
  }
  return target;
}

const ruleInput = z.string().min(1).describe('ACL rule id or exact name');

async function findRule(deps: WriteDeps, site: Site, query: string) {
  const rules = await deps.official.listAcl(site.id);
  const match = lookup(rules, query, [(r, q) => sameText(r.id, q), (r, q) => sameText(r.name, q)]);
  if ('ambiguous' in match)
    return ambiguous(query, match.ambiguous, (r: AclRule) => ({ id: r.id, name: r.name }));
  if ('none' in match) {
    const known = rules.length
      ? `the ACL rules are: ${rules.map((r) => r.name).join(', ')}`
      : 'the console has no ACL rules';
    throw new Error(`No ACL rule matches "${query}"; ${known}`);
  }
  assertUserDefined('ACL rule', `"${match.found.name}"`, match.found.metadata);
  return match.found;
}

const PROTECTED_NOTE =
  'A rule that can match a protected network (UNIFI_MCP_PROTECTED_NETWORKS, pi-cluster by default) needs confirm: true: one naming it or an address in its subnet, a network the console does not have, or an endpoint that is open (no filter, ports only, MACs) and so matches any address.';

export function createAclWriteTools(deps: WriteDeps): ToolDefinition[] {
  const known = async (site: Site) =>
    new Set((await deps.official.listNetworks(site.id)).map((n) => n.id));
  return [
    defineTool({
      name: 'unifi_create_acl_rule',
      description: `Create a switch ACL rule (official POST /acl-rules). Easy, unless it can match a protected network. ${PROTECTED_NOTE}`,
      inputSchema: {
        site: siteInput,
        ...partial(aclFields),
        name: aclFields.name,
        action: aclFields.action,
        type: aclFields.type.default('IPV4'),
        enabled: aclFields.enabled.default(true),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: false }),
      handler: async ({ site: wanted, confirm, ...a }) => {
        const site = await deps.sites.resolve(wanted);
        const body = compact(a as Plain);
        return guarded(
          {
            level: 'easy',
            target: aclTarget(body, await known(site)),
            confirm,
            preview: async () => ({ would: 'create ACL rule', aclRule: body }),
            run: async () => {
              const id = await deps.official.createFirewallObject(site.id, 'acl', body);
              return { changed: 'created', aclRule: { id, name: a.name } };
            },
          },
          await deps.scope(),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_update_acl_rule',
      description: `Change fields of a user-defined ACL rule; the tool reads it, merges and PUTs the whole rule. Always needs confirm: true; without it the tool previews the changed fields. Rules UniFi made are refused. ${PROTECTED_NOTE}`,
      inputSchema: {
        site: siteInput,
        aclRule: ruleInput,
        ...partial(aclFields),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, aclRule, confirm, ...patch }) => {
        const site = await deps.sites.resolve(wanted);
        const rule = await findRule(deps, site, aclRule);
        if ('ambiguous' in rule) return rule;
        const current = await deps.official.getFirewallObject(site.id, 'acl', rule.id);
        const { body, changes } = mergeUpdate(current, compact(patch as Plain), ACL_READ_ONLY);
        const fields = Object.keys(changes);
        if (fields.length === 0) return { unchanged: true, aclRule: rule.name };
        return guarded(
          {
            level: 'confirm',
            target: unionTargets(
              aclTarget(current, await known(site)),
              aclTarget(body, await known(site)),
            ),
            confirm,
            preview: async () => ({ would: 'update ACL rule', aclRule: rule.name, changes }),
            run: async () => {
              await deps.official.updateFirewallObject(site.id, 'acl', rule.id, body);
              return { changed: 'updated', aclRule: rule.name, fields };
            },
          },
          await deps.scope(),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_delete_acl_rule',
      description:
        'Delete a user-defined ACL rule (official DELETE). Always needs confirm: true; without it the tool previews. Rules UniFi made are refused.',
      inputSchema: { site: siteInput, aclRule: ruleInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, aclRule, confirm }) => {
        const site = await deps.sites.resolve(wanted);
        const rule = await findRule(deps, site, aclRule);
        if ('ambiguous' in rule) return rule;
        return guarded(
          {
            level: 'confirm',
            target: aclTarget(rule as unknown as Plain, await known(site)),
            confirm,
            preview: async () => ({ would: 'delete ACL rule', aclRule: rule.name }),
            run: async () => {
              await deps.official.deleteFirewallObject(site.id, 'acl', rule.id);
              return { changed: 'deleted', aclRule: rule.name };
            },
          },
          await deps.scope(),
          [],
        );
      },
    }),
  ];
}
