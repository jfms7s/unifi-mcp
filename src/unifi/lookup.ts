import type { ClientRecord } from './clients.js';
import type { OfficialDevice } from './official.js';

export type Match<T> = { found: T } | { ambiguous: T[] } | { none: true };

const squashMac = (value: string) => value.toLowerCase().replace(/[^0-9a-f]/g, '');

/** Case-insensitive equality; MACs compare without separators. */
export function sameId(a: string | undefined, b: string): boolean {
  if (a === undefined) return false;
  return a.toLowerCase() === b.toLowerCase() || (!b.includes('.') && squashMac(b).length === 12 && squashMac(a) === squashMac(b));
}

export const sameText = (a: string | undefined, b: string): boolean =>
  a !== undefined && a.toLowerCase() === b.toLowerCase();

export const hasText = (a: string | undefined, b: string): boolean =>
  a !== undefined && a.toLowerCase().includes(b.toLowerCase());

/**
 * Finds one item by looking through `tiers` from the most to the least exact.
 * The first tier with any match decides: one match is the answer, several are
 * returned as candidates rather than guessed between.
 */
export function lookup<T>(items: T[], query: string, tiers: Array<(item: T, query: string) => boolean>): Match<T> {
  for (const tier of tiers) {
    const hits = items.filter((item) => tier(item, query));
    if (hits.length === 1) return { found: hits[0] as T };
    if (hits.length > 1) return { ambiguous: hits };
  }
  return { none: true };
}

/** Device by id, MAC, IP, then exact and partial name. */
export const findDevice = (devices: OfficialDevice[], query: string): Match<OfficialDevice> =>
  lookup(devices, query, [
    (d, q) => sameText(d.id, q),
    (d, q) => sameId(d.macAddress, q),
    (d, q) => d.ipAddress === q,
    (d, q) => sameText(d.name, q),
    (d, q) => hasText(d.name, q),
  ]);

/** Client by id, MAC, IP, then exact and partial name. */
export const findClient = (clients: ClientRecord[], query: string): Match<ClientRecord> =>
  lookup(clients, query, [
    (c, q) => sameText(c.id, q) || sameText(c.officialId, q),
    (c, q) => sameId(c.mac, q),
    (c, q) => c.ip === q,
    (c, q) => sameText(c.name, q),
    (c, q) => hasText(c.name, q),
  ]);

/** What a tool returns when a name matches several things: the candidates, never a guess. */
export function ambiguous<T>(query: string, candidates: T[], row: (c: T) => unknown) {
  return {
    ambiguous: true as const,
    message: `"${query}" matches ${candidates.length}; ask again with its id or IP`,
    candidates: candidates.map(row),
  };
}
