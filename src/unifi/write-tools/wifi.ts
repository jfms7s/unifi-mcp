import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded, type ProtectedScope, type Target } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { WifiBroadcast } from '../official.js';
import { compact } from '../shape.js';
import type { Site } from '../sites.js';
import { partial, write, type WriteDeps } from './common.js';
import {
  hidingSecrets,
  protectedNetworkTarget,
  secretsIn,
  wholeUpdate,
  type Plain,
} from './objects.js';

/**
 * GET fields the `Wifi broadcast create or update` schema has none of
 * (10.6.109, STANDARD and IOT_OPTIMIZED): server-assigned, so left out of the PUT.
 */
export const WIFI_READ_ONLY = ['id', 'metadata'] as const;

const nested = (what: string) =>
  z.record(z.string(), z.unknown()).describe(`${what} (official request schema)`);

const networkRef = z
  .object({
    type: z.enum(['NATIVE', 'SPECIFIC']),
    networkId: z.guid().optional().describe('SPECIFIC only: the network id'),
  })
  .describe('Which network the SSID puts clients on: NATIVE (the default network) or SPECIFIC');

const SECURITY_HELP =
  'Security: {type OPEN|WPA2_PERSONAL|WPA3_PERSONAL|WPA2_WPA3_PERSONAL|WPA2_ENTERPRISE|..., passphrase (8-63), pmfMode, presharedKeys, ...}. The passphrase is never shown back.';

/** Fields of `Wifi broadcast create or update` that the create may leave to the console. */
const wifiFields = {
  network: networkRef,
  channel2gLockedTo6: z.boolean(),
  dtimPeriod2gLockedTo3: z.boolean(),
  broadcastingFrequenciesGHz: z
    .array(z.union([z.literal(2.4), z.literal(5), z.literal(6)]))
    .min(1)
    .describe('STANDARD only (required there): bands to broadcast on'),
  advertiseDeviceName: z.boolean().describe('STANDARD only (required there)'),
  arpProxyEnabled: z.boolean().describe('STANDARD only (required there)'),
  bssTransitionEnabled: z.boolean().describe('STANDARD only (required there)'),
  bandSteeringEnabled: z.boolean(),
  mloEnabled: z.boolean(),
  basicDataRateKbpsByFrequencyGHz: nested('Minimum data rates'),
  blackoutScheduleConfiguration: nested('Blackout schedule'),
  broadcastingDeviceFilter: nested('Which APs broadcast it'),
  clientFilteringPolicy: nested('MAC filtering'),
  mdnsProxyConfiguration: nested('mDNS proxy'),
  multicastFilteringPolicy: nested('Multicast filtering'),
  dnsAssistanceConfiguration: nested('DNS assistance'),
  dtimPeriodByFrequencyGHzOverride: nested('DTIM periods'),
  handoffSuggestionsConfiguration: nested('Handoff suggestions'),
  hotspotConfiguration: nested('Hotspot (captive portal, Passpoint)'),
};

/** Fields the request schema requires of every broadcast type. */
const requiredFields = {
  name: z.string().min(1).describe('SSID'),
  type: z.enum(['STANDARD', 'IOT_OPTIMIZED']),
  enabled: z.boolean(),
  hideName: z.boolean(),
  clientIsolationEnabled: z.boolean(),
  multicastToUnicastConversionEnabled: z.boolean(),
  uapsdEnabled: z.boolean(),
};

const wifiInput = z.string().min(1).describe('WiFi broadcast SSID (name) or id');

const wifiRow = (w: WifiBroadcast) => ({ id: w.id, name: w.name, enabled: w.enabled });

async function findWifi(
  deps: WriteDeps,
  site: Site,
  query: string,
): Promise<WifiBroadcast | ReturnType<typeof ambiguous>> {
  const all = await deps.official.listWifi(site.id);
  const match = lookup(all, query, [(w, q) => sameText(w.id, q), (w, q) => sameText(w.name, q)]);
  if ('ambiguous' in match) return ambiguous(query, match.ambiguous, wifiRow);
  if ('none' in match) {
    throw new Error(
      `No WiFi broadcast matches "${query}"; the broadcasts are: ${all.map((w) => w.name).join(', ')}`,
    );
  }
  return match.found;
}

/**
 * Every network a broadcast puts clients on: its own network reference
 * (NATIVE is the default network) and each pre-shared key's. A reference it
 * can't resolve (missing, an unknown type, SPECIFIC without a networkId,
 * NATIVE on a console with no default network) makes it `unplaced`: it may
 * be a protected network, and the guard says so rather than read it as none.
 */
function servedNetworks(
  broadcast: Plain,
  defaultNetworkId: string | undefined,
): { ids: string[]; unplaced: boolean } {
  const idOf = (ref: unknown): string | undefined => {
    const r = (ref ?? {}) as { type?: unknown; networkId?: unknown };
    if (r.type === 'SPECIFIC') return typeof r.networkId === 'string' ? r.networkId : undefined;
    return r.type === 'NATIVE' ? defaultNetworkId : undefined;
  };
  const keys = (broadcast.securityConfiguration as { presharedKeys?: unknown } | undefined)
    ?.presharedKeys;
  const psk = Array.isArray(keys) ? keys.map((k) => idOf((k as Plain | null)?.network)) : [];
  const all = [idOf(broadcast.network), ...psk];
  const ids = all.filter((id): id is string => id !== undefined);
  return { ids, unplaced: ids.length < all.length };
}

/** The guard's target and fail-closed reason for a change to broadcasts in `states`. */
function wifiGuard(
  name: string,
  states: Plain[],
  defaultNetworkId: string | undefined,
  scope: ProtectedScope,
): { target?: Target; reason?: string } {
  const served = states.map((s) => servedNetworks(s, defaultNetworkId));
  const target = protectedNetworkTarget(
    served.flatMap((s) => s.ids),
    scope,
  );
  if (target) return { target };
  return served.some((s) => s.unplaced)
    ? { reason: `can't place broadcast ${name}'s network, so it may serve a protected network` }
    : {};
}

/** The broadcast type picks the request variant: the console can't switch it in place. */
function refuseTypeChange(current: Plain, patch: Plain): void {
  if (patch.type !== undefined && patch.type !== current.type) {
    throw new Error(
      `delete and recreate the broadcast to change its type (${String(current.type)} → ${String(patch.type)})`,
    );
  }
}

const LOCKOUT_NOTE =
  'A broadcast that serves a protected network (pi-cluster by default), directly or through a pre-shared key, before or after the change, carries a lock-out warning.';

export function createWifiWriteTools(deps: WriteDeps): ToolDefinition[] {
  /** GET, merge, guard, PUT: shared by update and enable/disable. */
  async function update(
    args: { site?: string; wifi: string; confirm?: true },
    patch: Plain,
    done: string,
  ): Promise<unknown> {
    const site = await deps.sites.resolve(args.site);
    const w = await findWifi(deps, site, args.wifi);
    if ('ambiguous' in w) return w;
    const [current, networks, scope] = await Promise.all([
      deps.official.getWifi(site.id, w.id),
      deps.official.listNetworks(site.id),
      deps.scope(),
    ]);
    refuseTypeChange(current, patch);
    const { body, changes } = wholeUpdate(current, patch, WIFI_READ_ONLY);
    const fields = Object.keys(changes);
    if (fields.length === 0) return { unchanged: true, wifi: w.name };
    const defaultId = networks.find((n) => n.default)?.id;
    return guarded(
      {
        level: 'confirm',
        ...wifiGuard(w.name, [current, body], defaultId, scope),
        confirm: args.confirm,
        preview: async () => ({ would: 'update wifi', wifi: w.name, changes }),
        run: () =>
          hidingSecrets([...secretsIn(patch), ...secretsIn(current)], async () => {
            await deps.official.updateWifi(site.id, w.id, body);
            return done === 'updated'
              ? { changed: done, wifi: w.name, fields }
              : { changed: done, wifi: w.name };
          }),
      },
      scope,
      [],
    );
  }

  return [
    defineTool({
      name: 'unifi_create_wifi',
      description: `Create a WiFi broadcast (SSID) (official POST /wifi/broadcasts), from the official \`Wifi broadcast create or update\` request. ${SECURITY_HELP}`,
      inputSchema: {
        site: siteInput,
        ...requiredFields,
        securityConfiguration: z
          .looseObject({
            type: z.enum([
              'OPEN',
              'WPA2_PERSONAL',
              'WPA3_PERSONAL',
              'WPA2_WPA3_PERSONAL',
              'WPA2_ENTERPRISE',
              'WPA3_ENTERPRISE',
              'WPA2_WPA3_ENTERPRISE',
            ]),
          })
          .describe(SECURITY_HELP),
        ...partial(wifiFields),
        channel2gLockedTo6: wifiFields.channel2gLockedTo6.default(false),
        dtimPeriod2gLockedTo3: wifiFields.dtimPeriod2gLockedTo3.default(false),
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, ...request }) => {
        const site = await deps.sites.resolve(wanted);
        const body = compact(request as Plain);
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'create wifi', wifi: body.name }),
            run: () =>
              hidingSecrets(secretsIn(body), async () => {
                const created = (await deps.official.createWifi(site.id, body)) as
                  Plain | undefined;
                return { changed: 'created', wifi: compact({ id: created?.id, name: body.name }) };
              }),
          },
          await deps.scope(),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_update_wifi',
      description: `Change fields of a WiFi broadcast. Give only what changes: nested objects merge into the current ones (one whose type changes is replaced). The tool reads the broadcast, merges and PUTs the whole object (the official PUT replaces it). Always needs confirm: true, since a typo can cut clients off; without it the tool previews the changed fields, before → after; a passphrase change shows only as "changed". ${LOCKOUT_NOTE}`,
      inputSchema: {
        site: siteInput,
        wifi: wifiInput,
        ...partial(requiredFields),
        securityConfiguration: nested(SECURITY_HELP).optional(),
        ...partial(wifiFields),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: ({ site, wifi, confirm, ...patch }) =>
        update({ site, wifi, confirm }, compact(patch as Plain), 'updated'),
    }),
    defineTool({
      name: 'unifi_set_wifi_enabled',
      description: `Turn a WiFi broadcast on or off (reads it, sets enabled, PUTs the whole object). Always needs confirm: true; without it the tool previews. ${LOCKOUT_NOTE}`,
      inputSchema: {
        site: siteInput,
        wifi: wifiInput,
        enabled: z.boolean().describe('true broadcasts the SSID, false stops it'),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: ({ site, wifi, confirm, enabled }) =>
        update({ site, wifi, confirm }, { enabled }, enabled ? 'enabled' : 'disabled'),
    }),
    defineTool({
      name: 'unifi_delete_wifi',
      description: `Delete a WiFi broadcast (official DELETE): its clients drop off. Always needs confirm: true; without it the tool previews. ${LOCKOUT_NOTE}`,
      inputSchema: { site: siteInput, wifi: wifiInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, wifi, confirm }) => {
        const site = await deps.sites.resolve(wanted);
        const w = await findWifi(deps, site, wifi);
        if ('ambiguous' in w) return w;
        const [current, networks, scope] = await Promise.all([
          deps.official.getWifi(site.id, w.id),
          deps.official.listNetworks(site.id),
          deps.scope(),
        ]);
        const defaultId = networks.find((n) => n.default)?.id;
        return guarded(
          {
            level: 'confirm',
            ...wifiGuard(w.name, [current], defaultId, scope),
            confirm,
            preview: async () =>
              compact({
                would: 'delete wifi',
                wifi: w.name,
                enabled: w.enabled,
                security: w.securityConfiguration.type,
              }),
            run: async () => {
              await deps.official.deleteWifi(site.id, w.id);
              return { changed: 'deleted', wifi: w.name };
            },
          },
          scope,
          [],
        );
      },
    }),
  ];
}
