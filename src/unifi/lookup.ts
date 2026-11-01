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
