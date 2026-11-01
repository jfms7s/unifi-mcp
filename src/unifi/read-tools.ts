import { z } from 'zod';
import { describeError } from '../http/errors.js';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { clientDetail, clientRow, loadClients, type ClientRecord } from './clients.js';
import { limitInput, parseTime, siteInput } from './inputs.js';
import { hasText, lookup, sameId, sameText } from './lookup.js';
import type { OfficialDevice } from './official.js';
import { EVENT_CEILING, DAY_MS, READ, coverageNote, severityRank, type ReadDeps } from './read-common.js';
import { compact, cut, isGatewayModel, modelName } from './shape.js';
import { createEventTools } from './event-tools.js';
import { createHostTools, createWanTools } from './wan-tools.js';

export type { ReadDeps };

const OFFLINE_STATES = new Set(['OFFLINE', 'CONNECTION_INTERRUPTED', 'ISOLATED']);

function ambiguous<T>(query: string, candidates: T[], row: (c: T) => unknown) {
  return {
    ambiguous: true as const,
    message: `"${query}" matches ${candidates.length}; ask again with a MAC, IP, id or the full name`,
    candidates: candidates.map(row),
  };
}

function deviceRow(d: OfficialDevice) {
  return compact({
    id: d.id,
    name: d.name,
    model: d.model,
    ip: d.ipAddress,
    state: d.state,
    firmware: d.firmwareVersion,
    updateAvailable: d.firmwareUpdatable,
  });
}

export function createReadTools(deps: ReadDeps): ToolDefinition[] {
  const { official, legacy, syslog, sites } = deps;
  const now = deps.now ?? Date.now;

  return [
    defineTool({
      name: 'unifi_overview',
      description:
        'The "is anything wrong?" entry point: console model and Network version, health per subsystem (WAN, LAN, WLAN, VPN), devices online/offline/upgradable, client counts, and how many HIGH or VERY_HIGH events the last 24 hours logged.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const to = now();
        const [info, health, devices, clients, recent] = await Promise.all([
          legacy.sysinfo(site.ref),
          legacy.health(site.ref),
          official.listDevices(site.id),
          official.listClients(site.id),
          syslog.scan(site.ref, {
            from: to - DAY_MS,
            to,
            ceiling: EVENT_CEILING,
            filter: (e) => severityRank(e.severity) >= severityRank('HIGH'),
          }),
        ]);
        const gateway = devices.find((d) => isGatewayModel(d.model));
        const offline = devices.filter((d) => OFFLINE_STATES.has(d.state));
        const online = devices.filter((d) => d.state === 'ONLINE');
        const countType = (type: string) => clients.filter((c) => c.type === type).length;
        return compact({
          site: site.name,
          console: compact({
            name: info.name ?? gateway?.name,
            model: gateway ? modelName(gateway.model) : undefined,
            firmware: gateway?.firmwareVersion,
          }),
          network: compact({ version: info.version, updateAvailable: info.update_available }),
          health: health.map(({ subsystem, status, ...rest }) =>
            compact({
              subsystem,
              status,
              wanIp: rest.wan_ip,
              isp: rest.isp_name,
              latencyMs: rest.latency,
              users: rest.num_user,
              guests: rest.num_guest,
              devicesDisconnected: rest.num_disconnected || undefined,
            }),
          ),
          devices: {
            total: devices.length,
            online: online.length,
            offline: offline.length,
            other: devices.length - online.length - offline.length,
            upgradable: devices.filter((d) => d.firmwareUpdatable).length,
          },
          offlineDevices: offline.length > 0 ? offline.map((d) => d.name) : undefined,
          clients: {
            total: clients.length,
            wired: countType('WIRED'),
            wireless: countType('WIRELESS'),
            other: clients.length - countType('WIRED') - countType('WIRELESS'),
          },
          recentHighEvents: recent.entries.length,
          ...(recent.truncatedAt === undefined
            ? {}
            : {
                recentHighEventsNote: `${coverageNote(recent.truncatedAt)}; the count is a floor`,
              }),
        });
      },
    }),

    defineTool({
      name: 'unifi_list_devices',
      description:
        "List the console's UniFi devices: name, model, IP, state, firmware (and whether an update exists), uptime, CPU and memory.",
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const devices = await official.listDevices(site.id);
        // An offline device has no statistics; its row simply lacks them.
        const stats = await Promise.allSettled(devices.map((d) => official.deviceStats(site.id, d.id)));
        return {
          site: site.name,
          devices: devices.map((d, i) => {
            const s = stats[i]?.status === 'fulfilled' ? stats[i].value : undefined;
            return compact({
              ...deviceRow(d),
              uptimeSec: s?.uptimeSec,
              cpuPct: s?.cpuUtilizationPct,
              memoryPct: s?.memoryUtilizationPct,
            });
          }),
        };
      },
    }),

    defineTool({
      name: 'unifi_get_device',
      description:
        'Show one device by name, MAC, IP or id: model, state, firmware, uptime, CPU/memory, uplink rate, features and interfaces, and the legacy adoption state. An ambiguous name returns the candidates.',
      inputSchema: {
        device: z.string().min(1).describe('Device name, MAC, IP address or id'),
        site: siteInput,
      },
      annotations: READ,
      handler: async ({ device, site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [devices, basic] = await Promise.all([
          official.listDevices(site.id),
          legacy.devicesBasic(site.ref),
        ]);
        const match = lookup(devices, device, [
          (d, q) => sameText(d.id, q),
          (d, q) => sameId(d.macAddress, q),
          (d, q) => d.ipAddress === q,
          (d, q) => sameText(d.name, q),
          (d, q) => hasText(d.name, q),
        ]);
        if ('none' in match) throw new Error(`No device matches "${device}"`);
        if ('ambiguous' in match) return ambiguous(device, match.ambiguous, deviceRow);
        const d = match.found;
        const [stats, legacyRow] = [
          await official.deviceStats(site.id, d.id).catch((e: unknown) => ({ error: describeError(e) })),
          basic.find((b) => sameId(b.mac, d.macAddress)),
        ];
        const s = 'error' in stats ? undefined : stats;
        return compact({
          ...deviceRow(d),
          mac: d.macAddress,
          features: d.features,
          interfaces: d.interfaces,
          type: legacyRow?.type,
          adopted: legacyRow?.adopted,
          disabled: legacyRow?.disabled,
          uptimeSec: s?.uptimeSec,
          lastHeartbeat: s?.lastHeartbeatAt,
          cpuPct: s?.cpuUtilizationPct,
          memoryPct: s?.memoryUtilizationPct,
          uplink: s?.uplink,
          statisticsError: 'error' in stats ? stats.error : undefined,
        });
      },
    }),

    defineTool({
      name: 'unifi_list_clients',
      description:
        'List clients (connected ones unless includeOffline or blocked is set), newest activity first: name, IP, network, wired or wireless, uplink, signal, first and last seen. No MACs; use unifi_get_client for those. Filter by network, AP/switch, wired, blocked or first seen since.',
      inputSchema: {
        site: siteInput,
        network: z.string().min(1).optional().describe('Network name (e.g. IoT)'),
        ap: z.string().min(1).optional().describe('Uplink AP or switch name, or its MAC'),
        wired: z.boolean().optional().describe('true for wired clients, false for wireless'),
        blocked: z.boolean().optional().describe('true for blocked clients only, false for unblocked'),
        firstSeenSince: z
          .string()
          .min(1)
          .optional()
          .describe('Only clients first seen after this: ISO 8601 or a span back from now such as 7d'),
        includeOffline: z
          .boolean()
          .default(false)
          .describe('Also list clients that are not connected now (implied by blocked: true)'),
        limit: limitInput(50, 500),
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        const since = a.firstSeenSince === undefined ? undefined : parseTime(a.firstSeenSince, now());
        const all = await loadClients(legacy, site.ref);
        const showOffline = a.includeOffline || a.blocked === true;
        const keep = (c: ClientRecord) =>
          (showOffline || c.connected) &&
          (a.network === undefined || sameText(c.network, a.network) || c.networkId === a.network) &&
          (a.wired === undefined || c.wired === a.wired) &&
          (a.blocked === undefined || c.blocked === a.blocked) &&
          (since === undefined || (c.firstSeen !== undefined && c.firstSeen >= since)) &&
          (a.ap === undefined ||
            hasText(c.station?.last_uplink_name, a.ap) ||
            sameId(c.station?.ap_mac, a.ap) ||
            sameId(c.station?.sw_mac, a.ap));
        const matched = all.filter(keep).sort((x, y) => (y.lastSeen ?? 0) - (x.lastSeen ?? 0));
        const { rows, truncated } = cut(matched, a.limit);
        return compact({
          site: site.name,
          total: matched.length,
          clients: rows.map(clientRow),
          truncated,
        });
      },
    }),

    defineTool({
      name: 'unifi_get_client',
      description:
        'Show one client by name, MAC, IP or id: network, AP or switch port, signal, rates, uptime, traffic and first/last seen. An ambiguous name returns the candidates, not a guess.',
      inputSchema: {
        client: z.string().min(1).describe('Client name, MAC, IP address or id'),
        site: siteInput,
      },
      annotations: READ,
      handler: async ({ client, site: wanted }) => {
        const site = await sites.resolve(wanted);
        const all = await loadClients(legacy, site.ref);
        const match = lookup(all, client, [
          (c, q) => sameText(c.id, q),
          (c, q) => sameId(c.mac, q),
          (c, q) => c.ip === q,
          (c, q) => sameText(c.name, q),
          (c, q) => hasText(c.name, q),
        ]);
        if ('none' in match) throw new Error(`No client matches "${client}"`);
        if ('ambiguous' in match) return ambiguous(client, match.ambiguous, clientRow);
        return clientDetail(match.found);
      },
    }),
    ...createWanTools(deps),
    ...createEventTools(deps),
    ...createHostTools(deps),
  ];
}
