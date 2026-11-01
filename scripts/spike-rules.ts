/** The spike's decisions, kept pure so tests can check them without a console. */
import type { Station } from '../src/unifi/legacy.js';

const SAFE_NETWORKS = new Set(['IoT']);
const PROTECTED_NETWORK = 'pi-cluster';
const PROTECTED_SUBNET = [192, 168, 0];
const DESKTOP_IP = '192.168.10.10';
const IDLE_BYTES_LIMIT = 5_000_000;
/** What a candidate must look like: a smart light, the least consequential thing to cut off. */
const LIGHT = /nanoleaf|light|lamp|bulb/i;
/** People's devices, network gear and anything safety-related are never touched. */
export const EXCLUDED =
  /phone|iphone|android|pixel|galaxy|samsung|laptop|macbook|mac|workstation|pc|tablet|ipad|watch|ap|switch|gateway|router|camera|cam|doorbell|alarm|smoke|lock|heater|heat|power|meter|cluster|sensor|siren|water|gas|fire|medical/i;

/** Dotted-quad IPv4 as four octets, or undefined for anything else (including empty). */
export function parseIpv4(ip: string | undefined): number[] | undefined {
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return undefined;
  const octets = ip.split('.').map(Number);
  return octets.every((o) => o <= 255) ? octets : undefined;
}

export function inPiCluster(octets: number[]): boolean {
  return PROTECTED_SUBNET.every((o, i) => octets[i] === o);
}

export interface Candidate {
  station: Station;
  index: number;
  network: string;
}

export function withNetwork(stations: Station[], names: Map<string, string>): Candidate[] {
  return stations.map((station, index) => ({
    station,
    index,
    network: (station.network_id && names.get(station.network_id)) ?? station.network ?? '',
  }));
}

export function isSafeTarget({ station: s, network }: Candidate): boolean {
  const octets = parseIpv4(s.ip);
  if (!octets || inPiCluster(octets) || s.ip === DESKTOP_IP) return false;
  if (network === PROTECTED_NETWORK) return false;
  if (!(SAFE_NETWORKS.has(network) || s.is_guest === true)) return false;
  const text = `${s.hostname ?? ''} ${s.name ?? ''} ${s.oui ?? ''}`;
  return (
    !s.is_wired &&
    LIGHT.test(text) &&
    !EXCLUDED.test(text) &&
    (s.tx_bytes ?? 0) + (s.rx_bytes ?? 0) < IDLE_BYTES_LIMIT &&
    s.blocked !== true
  );
}

export function pickClient(candidates: Candidate[]): Candidate | undefined {
  return candidates.find(isSafeTarget);
}

/**
 * Whether a client is verifiably unblocked. `blocked` is rest/user's value for
 * the MAC: undefined means the client was not found or the check failed, which
 * is never read as unblocked.
 */
export function isVerifiedUnblocked(blocked: boolean | undefined): boolean {
  return blocked === false;
}
