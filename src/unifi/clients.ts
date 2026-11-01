import type { KnownClient, LegacyApi } from './legacy.js';
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
  firstSeen?: number;
  lastSeen?: number;
  station?: Station;
}

/** rest/user (everyone ever seen) + stat/sta (who is connected) + network names. */
export async function loadClients(legacy: LegacyApi, ref: string): Promise<ClientRecord[]> {
  const [known, stations, networks] = await Promise.all([
    legacy.knownClients(ref),
    legacy.stations(ref),
    legacy.networkConf(ref),
  ]);
  const byMac = new Map(stations.map((s) => [s.mac.toLowerCase(), s]));
  const networkName = new Map(networks.map((n) => [n._id, n.name]));
  return known.map((k: KnownClient) => {
    const station = byMac.get(k.mac.toLowerCase());
    return {
      id: k.id,
      mac: k.mac,
      name: k.name,
      ip: k.ip,
      networkId: k.networkId,
      network: station?.network ?? (k.networkId ? networkName.get(k.networkId) : undefined),
      connected: station !== undefined,
      wired: station?.is_wired,
      blocked: k.blocked,
      firstSeen: k.firstSeen === undefined ? undefined : k.firstSeen * 1000,
      lastSeen: k.lastSeen === undefined ? undefined : k.lastSeen * 1000,
      station,
    };
  });
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
