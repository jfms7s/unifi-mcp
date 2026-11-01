import { describeError } from '../http/errors.js';
import type { KnownClient, LegacyApi } from './legacy.js';
import type { OfficialApi } from './official.js';
import { sameId } from './lookup.js';
import { compact, iso } from './shape.js';
import type { Station } from './schemas.js';

/** A client the console has seen, joined with what it is doing now when it is connected. */
export interface ClientRecord {
  id: string;
  mac: string;
  name: string;
  ip?: string;
  network?: string;
  networkId?: string;
  connected: boolean;
  wired?: boolean;
  blocked: boolean;
  /** The official API's client id, which guest authorization needs. */
  officialId?: string;
  /** Official `access.type`, e.g. DEFAULT or GUEST. */
  access?: string;
  firstSeen?: number;
  lastSeen?: number;
  station?: Station;
}

export interface LoadedClients {
  records: ClientRecord[];
  /**
   * Set when the official client list failed: the records are legacy-only, with
   * no `officialId`, so guest actions can't run until it answers again.
   */
  note?: string;
}

/** Why the client tools carry legacy-only records: the official list failed. */
export const officialClientsNote = (error: unknown) =>
  `the official client list didn't answer (${describeError(error)}); guest actions are unavailable until it does`;

/**
 * rest/user (everyone ever seen) + stat/sta (who is connected) + network names
 * + official ids. A failing official list degrades to legacy-only records and
 * a note rather than failing every client tool.
 */
export async function loadClients(
  { legacy, official }: { legacy: LegacyApi; official: OfficialApi },
  site: { id: string; ref: string },
): Promise<LoadedClients> {
  const [stations, networks, officialResult] = await Promise.all([
    legacy.stations(site.ref),
    legacy.networkConf(site.ref),
    official.listClients(site.id).then(
      (clients) => ({ clients }),
      (error: unknown) => ({ clients: [], note: officialClientsNote(error) }),
    ),
  ]);
  const officialClients = officialResult.clients;
  const known = await legacy.knownClients(site.ref, stations);
  const byMac = new Map(stations.map((s) => [s.mac.toLowerCase(), s]));
  const networkName = new Map(networks.map((n) => [n._id, n.name]));
  const records = known.map((k: KnownClient): ClientRecord => {
    const station = byMac.get(k.mac.toLowerCase());
    const match = officialClients.find((o) => sameId(o.macAddress, k.mac));
    return {
      id: k.id,
      mac: k.mac,
      name: k.name,
      ip: k.ip,
      networkId: k.networkId,
      network: station?.network ?? (k.networkId ? networkName.get(k.networkId) : undefined),
      connected: station !== undefined,
      wired: k.wired,
      blocked: k.blocked,
      officialId: match?.id,
      access: match?.access?.type,
      firstSeen: k.firstSeen === undefined ? undefined : k.firstSeen * 1000,
      lastSeen: k.lastSeen === undefined ? undefined : k.lastSeen * 1000,
      station,
    };
  });
  return 'note' in officialResult ? { records, note: officialResult.note } : { records };
}

/** One compact row: no MAC, no radio detail. */
export function clientRow(c: ClientRecord) {
  const s = c.station;
  return compact({
    id: c.id,
    // A client with no name is named by its MAC; a list row must not carry one.
    name: c.name === c.mac ? '(unnamed)' : c.name,
    ip: c.ip,
    network: c.network,
    connected: c.connected,
    wired: c.wired,
    blocked: c.blocked,
    uplink: s?.last_uplink_name,
    signalDbm: s?.is_wired === false ? s.signal : undefined,
    firstSeen: iso(c.firstSeen),
    lastSeen: iso(c.lastSeen),
  });
}

/** Everything known about one client, MAC included. */
export function clientDetail(c: ClientRecord) {
  const s = c.station;
  const mbps = (kbps: number | undefined) => (kbps === undefined ? undefined : kbps / 1000);
  return compact({
    ...clientRow(c),
    mac: c.mac,
    officialId: c.officialId,
    access: c.access,
    vendor: s?.oui,
    hostname: s?.hostname,
    guest: s?.is_guest,
    essid: s?.essid,
    apMac: s?.ap_mac,
    radio: s?.radio,
    channel: s?.channel,
    rssi: s?.rssi,
    txRateMbps: mbps(s?.tx_rate),
    rxRateMbps: mbps(s?.rx_rate),
    satisfaction: s?.satisfaction,
    switchMac: s?.sw_mac,
    switchPort: s?.sw_port,
    uptimeSec: s?.uptime,
    txBytes: s?.tx_bytes,
    rxBytes: s?.rx_bytes,
  });
}
