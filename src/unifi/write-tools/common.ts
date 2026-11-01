import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { ProtectedScope } from '../guard.js';
import type { ReadDeps } from '../read-common.js';

export interface WriteDeps extends ReadDeps {
  /** The protected scope; lazy and cached for a few minutes (see `lazyScope`). */
  scope: () => Promise<ProtectedScope>;
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
 * Loads the scope on first use and keeps it for `SCOPE_TTL_MS`, then loads it
 * again so a device adopted later or a subnet change is seen without a
 * restart. A failed load (an unknown protected network name, the console
 * unreachable) is not kept, so the next change tries again rather than
 * running unguarded.
 */
export function lazyScope(load: () => Promise<ProtectedScope>): () => Promise<ProtectedScope> {
  let cached: { scope: Promise<ProtectedScope>; loadedAt: number } | undefined;
  return () => {
    if (!cached || Date.now() - cached.loadedAt >= SCOPE_TTL_MS) {
      const entry = {
        loadedAt: Date.now(),
        scope: load().catch((error: unknown) => {
          if (cached === entry) cached = undefined;
          throw error;
        }),
      };
      cached = entry;
    }
    return cached.scope;
  };
}

/** Every field of a raw zod shape made optional: an update's "partial of the request schema". */
export const partial = <T extends Record<string, z.ZodType>>(shape: T) =>
  Object.fromEntries(Object.entries(shape).map(([k, v]) => [k, v.optional()])) as {
    [K in keyof T]: z.ZodOptional<T[K]>;
  };
