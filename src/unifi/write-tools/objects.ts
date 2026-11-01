// GET-merge-PUT for the official API's whole-object updates (networks, WiFi
// broadcasts): the PUT replaces the object, so an update merges the caller's
// partial into what GET returned and sends all of it back. The preview shows
// only what changed, with secrets (WiFi passphrases) never shown.

import { touchesProtected, type ProtectedScope, type Target } from '../guard.js';

export type Plain = Record<string, unknown>;

/** A field change in a preview: before → after, or just "changed" for a secret. */
export type Change = { before: unknown; after: unknown } | 'changed';

export const REDACTED = '<redacted>';

/** Keys whose values are never shown: WiFi passphrases and their kin. */
const SECRET_KEY = /pass(phrase|word)|secret/i;

/** Nested objects whose variant these fields pick are replaced, not merged. */
const DISCRIMINATORS = ['type', 'mode', 'management'];

const isPlain = (v: unknown): v is Plain =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

function same(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => same(x, b[i]));
  }
  if (isPlain(a) && isPlain(b)) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    return [...keys].every((k) => same(a[k], b[k]));
  }
  return a === b;
}

/**
 * `patch` laid over `base`: nested objects merge, arrays and scalars replace.
 * A nested object whose discriminator changes (`type`, `mode`) is replaced
 * whole, so a DHCP SERVER block never keeps its range after becoming RELAY.
 */
export function merge(base: Plain, patch: Plain): Plain {
  const out: Plain = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    const old = out[key];
    const switches = (o: Plain, p: Plain) => DISCRIMINATORS.some((d) => d in p && p[d] !== o[d]);
    out[key] = isPlain(value) && isPlain(old) && !switches(old, value) ? merge(old, value) : value;
  }
  return out;
}

/** A deep copy with every secret value replaced by `<redacted>`. */
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (!isPlain(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [
      k,
      SECRET_KEY.test(k) && v != null ? REDACTED : redact(v),
    ]),
  );
}

/** Every secret string in `value`, to scrub from error messages. */
export function secretsIn(value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((v) => secretsIn(v, found));
  else if (isPlain(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY.test(k) && typeof v === 'string' && v) found.push(v);
      else secretsIn(v, found);
    }
  }
  return found;
}

/**
 * The fields that differ, by dotted path, with before → after. Arrays count
 * as one field. A secret, or a value that only differs inside a secret, shows
 * as "changed" and never as its value.
 */
export function diff(before: Plain, after: Plain, prefix = ''): Record<string, Change> {
  const out: Record<string, Change> = {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const b = before[key];
    const a = after[key];
    const path = prefix + key;
    if (isPlain(b) && isPlain(a)) {
      Object.assign(out, diff(b, a, `${path}.`));
      continue;
    }
    if (same(a, b)) continue;
    const [rb, ra] = [redact(b), redact(a)];
    out[path] =
      SECRET_KEY.test(key) || same(rb, ra) ? 'changed' : { before: rb ?? null, after: ra ?? null };
  }
  return out;
}

const without = (obj: Plain, keys: readonly string[]): Plain =>
  Object.fromEntries(Object.entries(obj).filter(([k]) => !keys.includes(k)));

/**
 * The PUT body and the field diff for an update. `readOnly` are the GET fields
 * the request schema has no place for (`id`, `metadata`, ...): they are left
 * out of the body and the diff.
 */
export function wholeUpdate(
  current: Plain,
  patch: Plain,
  readOnly: readonly string[],
): { body: Plain; changes: Record<string, Change> } {
  const base = without(current, readOnly);
  const body = merge(base, without(patch, readOnly));
  return { body, changes: diff(base, body) };
}

/** Runs `fn`; an error whose message carries one of `secrets` is rethrown with them redacted. */
export async function hidingSecrets<T>(secrets: string[], fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (!(error instanceof Error) || !secrets.some((s) => error.message.includes(s))) throw error;
    const message = secrets.reduce((m, s) => m.split(s).join(REDACTED), error.message);
    throw new Error(message);
  }
}

/** The first of these networks a change to which touches a protected one, as a guard target. */
export function protectedNetworkTarget(
  networkIds: Iterable<string>,
  scope: ProtectedScope,
): Target | undefined {
  for (const id of networkIds) {
    const target: Target = { kind: 'network', id };
    if (touchesProtected(target, scope, []) !== undefined) return target;
  }
  return undefined;
}
