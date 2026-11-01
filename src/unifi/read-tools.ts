import { z } from 'zod';
import { describeError } from '../http/errors.js';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { clientDetail, clientRow, loadClients, type ClientRecord } from './clients.js';
import { limitInput, parseTime, siteInput } from './inputs.js';
import { ambiguous, findClient, findDevice, hasText, sameId, sameText } from './lookup.js';
import type { LegacyDevice } from './legacy.js';
import type { OfficialDevice } from './official.js';
import { EVENT_CEILING, DAY_MS, READ, coverageNote, severityRank, type ReadDeps } from './read-common.js';
import { compact, cut, isGatewayModel, modelName } from './shape.js';
import { createEventTools } from './event-tools.js';
import { createMetricsTools } from './metrics-tools.js';
import { createSecurityTools } from './security-tools.js';
import { createThreatTools } from './threat-tools.js';
import { createHostTools, createWanTools } from './wan-tools.js';

export type { ReadDeps };

const OFFLINE_STATES = new Set(['OFFLINE', 'CONNECTION_INTERRUPTED', 'ISOLATED']);

const BANDS: Record<string, string> = { ng: '2.4 GHz', na: '5 GHz', '6e': '6 GHz', ad: '60 GHz' };
const GATEWAY_TYPES = new Set(['udm', 'ugw', 'uxg', 'ucg', 'udr']);

/**
 * The list's one-glance summary of a device from stat/device: what it hangs
 * off (parent name and port, or WAN for the gateway), ports up and PoE in use
 * for a switch or gateway, and each radio's band, channel and clients for an AP.
 */
function deviceSummary(d: OfficialDevice, legacyRows: LegacyDevice[], devices: OfficialDevice[]) {
  const row = legacyRows.find((l) => sameId(l.mac, d.macAddress));
  if (!row) return {};
  const parentName = (m: string) =>
    devices.find((o) => sameId(o.macAddress, m))?.name ??
    legacyRows.find((l) => sameId(l.mac, m))?.name ??
    'an unknown device';
  const uplink = row.uplinkMac
    ? `${parentName(row.uplinkMac)} port ${row.uplinkPort ?? '?'}`
    : isGatewayModel(d.model) || GATEWAY_TYPES.has(row.type ?? '')
      ? 'WAN'
      : row.lastUplinkMac
        ? `${parentName(row.lastUplinkMac)} port ${row.lastUplinkPort ?? '?'} (last seen)`
        : undefined;
  const poeCapable = row.ports.filter((p) => p.poeInUse !== undefined);
  return compact({
    uplink,
    ports:
      row.ports.length === 0
        ? undefined
        : compact({
            up: row.ports.filter((p) => p.up).length,
            total: row.ports.length,
            poeInUse: poeCapable.length ? poeCapable.filter((p) => p.poeInUse).length : undefined,
          }),
    radios:
      row.radios.length === 0
        ? undefined
        : row.radios.map((r) =>
            compact({ band: BANDS[r.radio] ?? r.radio, channel: r.channel, clients: r.clients }),
          ),
  });
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
        "List the console's UniFi devices: name, model, IP, state, firmware (and whether an update exists), uptime, CPU and memory, plus what each hangs off (parent and port, or WAN), ports up and PoE ports in use, and each AP radio's band, channel and clients.",
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [devices, legacyRows] = await Promise.all([
          official.listDevices(site.id),
          legacy.devices(site.ref).catch((e: unknown) => ({ error: describeError(e) })),
        ]);
        // An offline device has no statistics; its row simply lacks them.
        const stats = await Promise.allSettled(devices.map((d) => official.deviceStats(site.id, d.id)));
        const rows = 'error' in legacyRows ? [] : legacyRows;
        return compact({
          site: site.name,
          devices: devices.map((d, i) => {
            const s = stats[i]?.status === 'fulfilled' ? stats[i].value : undefined;
            return compact({
              ...deviceRow(d),
              ...deviceSummary(d, rows, devices),
              uptimeSec: s?.uptimeSec,
              cpuPct: s?.cpuUtilizationPct,
              memoryPct: s?.memoryUtilizationPct,
            });
          }),
          note:
            'error' in legacyRows
              ? `uplink, port and radio summary unavailable: ${legacyRows.error}`
              : undefined,
        });
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
        const match = findDevice(devices, device);
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
        const all = await loadClients(deps, site);
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
        const all = await loadClients(deps, site);
        const match = findClient(all, client);
        if ('none' in match) throw new Error(`No client matches "${client}"`);
        if ('ambiguous' in match) return ambiguous(client, match.ambiguous, clientRow);
        return clientDetail(match.found);
      },
    }),
    ...createWanTools(deps),
    ...createEventTools(deps),
    ...createThreatTools(deps),
    ...createSecurityTools(deps),
    ...createMetricsTools(deps),
    ...createHostTools(deps),
  ];
}
