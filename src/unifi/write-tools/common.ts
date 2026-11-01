import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { ProtectedScope } from '../guard.js';
import type { ReadDeps } from '../read-common.js';
import type { Site } from '../sites.js';

export interface WriteDeps extends ReadDeps {
  /**
   * The protected scope of a site; lazy and cached per site for a few minutes
   * (see `lazyScope`). Every write passes the site it resolved.
   */
  scope: (site: Site) => Promise<ProtectedScope>;
  /** The console's hostname from UNIFI_URL (see `consoleHost`); absent when it is an IP. */
  consoleHost?: string;
}

/**
 * The host unifi-mcp reaches the console by, lower-cased, when UNIFI_URL names
 * a hostname; undefined for an IP address, which no DNS record can redirect.
 */
export function consoleHost(baseUrl: string): string | undefined {
  const host = new URL(baseUrl).hostname.toLowerCase();
  if (host.startsWith('[') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return undefined;
  return host;
}

/** Annotations for a change; `destructive` when it cuts something off or resets it. */
export function write(opts: { destructive: boolean; idempotent: boolean }): ToolAnnotations {
  return {
    readOnlyHint: false,
    destructiveHint: opts.destructive,
    idempotentHint: opts.idempotent,
    openWorldHint: false,
  };
}

/** How long a loaded scope is trusted: long enough to spare the console, short enough to see a new device or subnet. */
export const SCOPE_TTL_MS = 5 * 60_000;

/**
 * Loads a site's scope on first use and keeps it for `SCOPE_TTL_MS`, then
 * loads it again so a device adopted later or a subnet change is seen without
 * a restart. Each site has its own entry, so a change on one site is never
 * checked against another site's networks. A failed load (an unknown
 * protected network name, the console unreachable) is not kept, so the next
 * change tries again rather than running unguarded.
 */
export function lazyScope(
  load: (site: Site) => Promise<ProtectedScope>,
): (site: Site) => Promise<ProtectedScope> {
  const cache = new Map<string, { scope: Promise<ProtectedScope>; loadedAt: number }>();
  return (site) => {
    const cached = cache.get(site.id);
    if (cached && Date.now() - cached.loadedAt < SCOPE_TTL_MS) return cached.scope;
    const entry = {
      loadedAt: Date.now(),
      scope: load(site).catch((error: unknown) => {
        if (cache.get(site.id) === entry) cache.delete(site.id);
        throw error;
      }),
    };
    cache.set(site.id, entry);
    return entry.scope;
  };
}

/** Every field of a raw zod shape made optional: an update's "partial of the request schema". */
export const partial = <T extends Record<string, z.ZodType>>(shape: T) =>
  Object.fromEntries(Object.entries(shape).map(([k, v]) => [k, v.optional()])) as {
    [K in keyof T]: z.ZodOptional<T[K]>;
  };
