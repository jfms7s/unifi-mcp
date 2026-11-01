import type { ClientRecord } from './clients.js';
import type { OfficialDevice } from './official.js';

/**
 * `ambiguous` is several matches, or, with `exactOnly`, a match on part of a
 * name only (`partial`): either way candidates to ask about, never acted on.
 */
export type Match<T> = { found: T } | { ambiguous: T[]; partial?: true } | { none: true };

export interface LookupOptions {
  /** Write tools: a partial-name match is returned as candidates, never as `found`. */
  exactOnly?: boolean;
}

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

/** The exact tiers first; a partial-name match is a candidate list under `exactOnly`. */
function lookupWithPartial<T>(
  items: T[],
  query: string,
  exact: Array<(item: T, query: string) => boolean>,
  partial: (item: T, query: string) => boolean,
  opts: LookupOptions,
): Match<T> {
  const match = lookup(items, query, exact);
  if (!('none' in match)) return match;
  if (!opts.exactOnly) return lookup(items, query, [partial]);
  const hits = items.filter((item) => partial(item, query));
  return hits.length > 0 ? { ambiguous: hits, partial: true } : { none: true };
}

/** Device by id, MAC, IP, then exact and partial name. */
export const findDevice = (
  devices: OfficialDevice[],
  query: string,
  opts: LookupOptions = {},
): Match<OfficialDevice> =>
  lookupWithPartial(
    devices,
    query,
    [
      (d, q) => sameText(d.id, q),
      (d, q) => sameId(d.macAddress, q),
      (d, q) => d.ipAddress === q,
      (d, q) => sameText(d.name, q),
    ],
    (d, q) => hasText(d.name, q),
    opts,
  );

/** Client by id, MAC, IP, then exact and partial name. */
export const findClient = (
  clients: ClientRecord[],
  query: string,
  opts: LookupOptions = {},
): Match<ClientRecord> =>
  lookupWithPartial(
    clients,
    query,
    [
      (c, q) => sameText(c.id, q) || sameText(c.officialId, q),
      (c, q) => sameId(c.mac, q),
      (c, q) => c.ip === q,
      (c, q) => sameText(c.name, q),
    ],
    (c, q) => hasText(c.name, q),
    opts,
  );

/**
 * What a tool returns when a name matches several things, or (`partial`) only
 * part of one in a write tool: the candidates, never a guess.
 */
export function ambiguous<T>(query: string, candidates: T[], row: (c: T) => unknown, partial = false) {
  return {
    ambiguous: true as const,
    message: partial
      ? `"${query}" is only part of a name; a change needs an exact name, id or IP. Ask again with one of these`
      : `"${query}" matches ${candidates.length}; ask again with its id or IP`,
    candidates: candidates.map(row),
  };
}
