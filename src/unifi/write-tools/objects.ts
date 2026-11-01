// GET-merge-PUT for the official API's whole-object updates (networks, WiFi
// broadcasts): the PUT replaces the object, so an update merges the caller's
// partial into what GET returned and sends all of it back. The preview shows
// only what changed, with secrets (WiFi passphrases, PSKs, keys) never shown.

import { UnifiApiError } from '../../http/errors.js';
import { touchesProtected, type ProtectedScope, type Target } from '../guard.js';

export type Plain = Record<string, unknown>;

/** A field change in a preview: before → after, or for a secret just "changed" or "removed". */
export type Change = { before: unknown; after: unknown } | 'changed' | 'removed';

export const REDACTED = '<redacted>';

/** Keys whose values are never shown: WiFi passphrases, PSKs and their kin. */
const SECRET_KEY = /pass|secret|psk/i;
/** `key`, `wpaKey`, `x_key`...: secret when it holds a string (a `keyCount` does not end in key). */
const KEY_NAME = /(^|[a-z_])key$/i;

const isSecret = (key: string, value: unknown): boolean =>
  SECRET_KEY.test(key) || (KEY_NAME.test(key) && typeof value === 'string');

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
      isSecret(k, v) && v != null ? REDACTED : redact(v),
    ]),
  );
}

/** Every secret string in `value`, to scrub from error messages. */
export function secretsIn(value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((v) => secretsIn(v, found));
  else if (isPlain(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (isSecret(k, v) && typeof v === 'string' && v) found.push(v);
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
    if (isSecret(key, a) || isSecret(key, b)) out[path] = a == null ? 'removed' : 'changed';
    else out[path] = same(rb, ra) ? 'changed' : { before: rb ?? null, after: ra ?? null };
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

const WITHHELD = 'details withheld because the request carried a passphrase';

/**
 * Runs `fn`, a write whose request carries `secrets`. If it fails, the
 * console's detail is never passed on: it may echo a passphrase escaped
 * (`ab\"cd`) or cut at the detail limit, where no search finds it. The error
 * keeps its kind, status and the console's `api.err.*` code.
 */
export async function hidingSecrets<T>(secrets: string[], fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (secrets.length === 0) throw error;
    if (!(error instanceof UnifiApiError)) throw new Error(`The change failed; ${WITHHELD}`);
    const code = /api\.err\.[A-Za-z0-9_.]+/.exec(error.detail)?.[0];
    const safeCode = code && !secrets.some((s) => code.includes(s)) ? `, ${code}` : '';
    const status = error.status === undefined ? '' : `HTTP ${error.status}`;
    const why = [status, safeCode.slice(2)].filter(Boolean).join(', ');
    throw new UnifiApiError({
      kind: error.kind,
      method: error.method,
      path: error.path,
      status: error.status,
      detail: `the console rejected the change${why ? ` (${why})` : ''}; ${WITHHELD}`,
    });
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
