import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { ProtectedScope } from '../guard.js';
import type { ReadDeps } from '../read-common.js';

export interface WriteDeps extends ReadDeps {
  /** The protected scope; lazy and cached per process (see `lazyScope`). */
  scope: () => Promise<ProtectedScope>;
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

/**
 * Loads the scope on first use and keeps it for the life of the process. A
 * failed load (an unknown protected network name, the console unreachable) is
 * not kept, so the next change tries again rather than running unguarded.
 */
export function lazyScope(load: () => Promise<ProtectedScope>): () => Promise<ProtectedScope> {
  let cached: Promise<ProtectedScope> | undefined;
  return () => {
    cached ??= load().catch((error: unknown) => {
      cached = undefined;
      throw error;
    });
    return cached;
  };
}

/** Every field of a raw zod shape made optional: an update's "partial of the request schema". */
export const partial = <T extends Record<string, z.ZodType>>(shape: T) =>
  Object.fromEntries(Object.entries(shape).map(([k, v]) => [k, v.optional()])) as {
    [K in keyof T]: z.ZodOptional<T[K]>;
  };
