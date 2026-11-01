import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { OfficialNetwork } from '../official.js';
import { compact } from '../shape.js';
import type { Site } from '../sites.js';
import { partial, write, type WriteDeps } from './common.js';
import { wholeUpdate, type Plain } from './objects.js';

/**
 * GET fields the `Create or update Network` schema has none of (10.6.109,
 * every management variant): server-assigned, so left out of the PUT.
 */
export const NETWORK_READ_ONLY = ['id', 'metadata', 'default'] as const;

const nested = (what: string) =>
  z.record(z.string(), z.unknown()).describe(`${what} (official request schema)`);

/** Top-level fields of `Create or update Network`, every variant (GATEWAY, SWITCH, UNMANAGED). */
const networkFields = {
  name: z.string().min(1).describe('Network name'),
  management: z.enum(['GATEWAY', 'SWITCH', 'UNMANAGED']).describe('Who routes it'),
  enabled: z.boolean().describe('false disables the network: its clients lose it'),
  vlanId: z.number().int().min(1).max(4009).describe('VLAN id'),
  cellularBackupEnabled: z.boolean(),
  internetAccessEnabled: z.boolean(),
  isolationEnabled: z.boolean().describe('Isolate the network from the others'),
  mdnsForwardingEnabled: z.boolean(),
  zoneId: z.guid().describe('Firewall zone id'),
  deviceId: z.guid().describe('SWITCH management only: the switch that routes it'),
  dhcpGuarding: nested('DHCP guarding'),
  ipv4Configuration: nested(
    'IPv4: hostIpAddress, prefixLength, autoScaleEnabled, dhcpConfiguration {mode SERVER|RELAY, ...}',
  ),
  ipv6Configuration: nested('IPv6 configuration'),
};

const networkInput = z.string().min(1).describe('Network name or id');

const networkRow = (n: OfficialNetwork) => ({ id: n.id, name: n.name, vlanId: n.vlanId });

async function findNetwork(
  deps: WriteDeps,
  site: Site,
  query: string,
): Promise<OfficialNetwork | ReturnType<typeof ambiguous>> {
  const networks = await deps.official.listNetworks(site.id);
  const match = lookup(networks, query, [
    (n, q) => sameText(n.id, q),
    (n, q) => sameText(n.name, q),
  ]);
  if ('ambiguous' in match) return ambiguous(query, match.ambiguous, networkRow);
  if ('none' in match) {
    throw new Error(
      `No network matches "${query}"; the networks are: ${networks.map((n) => n.name).join(', ')}`,
    );
  }
  return match.found;
}

const LOCKOUT_NOTE =
  'Changing or disabling a protected network (pi-cluster by default) can cut unifi-mcp off; its preview says so.';

export function createNetworkWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [
    defineTool({
      name: 'unifi_create_network',
      description:
        'Create a network (official POST /networks). Takes the official `Create or update Network` request: GATEWAY networks also need cellularBackupEnabled, internetAccessEnabled, isolationEnabled and ipv4Configuration.',
      inputSchema: {
        site: siteInput,
        ...partial(networkFields),
        name: networkFields.name,
        management: networkFields.management,
        vlanId: networkFields.vlanId,
        enabled: networkFields.enabled.default(true),
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, ...request }) => {
        const site = await deps.sites.resolve(wanted);
        const body = compact(request as Plain);
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'create network', network: body }),
            run: async () => {
              const created = (await deps.official.createNetwork(site.id, body)) as
                Plain | undefined;
              return {
                changed: 'created',
                network: compact({ id: created?.id, name: body.name, vlanId: body.vlanId }),
              };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_update_network',
      description: `Change fields of a network. Give only what changes: nested objects merge into the current ones (a nested object whose mode or type changes is replaced). The tool reads the network, merges and PUTs the whole object (the official PUT replaces it). Always needs confirm: true, since a typo can cut clients off; without it the tool previews the changed fields, before → after. ${LOCKOUT_NOTE}`,
      inputSchema: {
        site: siteInput,
        network: networkInput,
        ...partial(networkFields),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, network, confirm, ...patch }) => {
        const site = await deps.sites.resolve(wanted);
        const n = await findNetwork(deps, site, network);
        if ('ambiguous' in n) return n;
        const current = await deps.official.getNetwork(site.id, n.id);
        // management picks the request variant: the console can't switch it in place.
        if (patch.management !== undefined && patch.management !== current.management) {
          throw new Error(
            `delete and recreate the network to change its management (${String(current.management)} → ${patch.management})`,
          );
        }
        const { body, changes } = wholeUpdate(current, compact(patch as Plain), NETWORK_READ_ONLY);
        const fields = Object.keys(changes);
        if (fields.length === 0) return { unchanged: true, network: n.name };
        return guarded(
          {
            level: 'confirm',
            target: { kind: 'network', id: n.id },
            confirm,
            preview: async () => ({ would: 'update network', network: n.name, changes }),
            run: async () => {
              await deps.official.updateNetwork(site.id, n.id, body);
              return { changed: 'updated', network: n.name, fields };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_delete_network',
      description: `Delete a network (official DELETE). Always needs confirm: true; without it the tool previews. The console refuses a network still in use. ${LOCKOUT_NOTE}`,
      inputSchema: { site: siteInput, network: networkInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, network, confirm }) => {
        const site = await deps.sites.resolve(wanted);
        const n = await findNetwork(deps, site, network);
        if ('ambiguous' in n) return n;
        return guarded(
          {
            level: 'confirm',
            target: { kind: 'network', id: n.id },
            confirm,
            preview: async () =>
              compact({
                would: 'delete network',
                network: n.name,
                vlanId: n.vlanId,
                enabled: n.enabled,
              }),
            run: async () => {
              await deps.official.deleteNetwork(site.id, n.id);
              return { changed: 'deleted', network: n.name };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
  ];
}
