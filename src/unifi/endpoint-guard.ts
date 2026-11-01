import type { z } from 'zod';
import type { HttpMethod, QueryParams, UnifiHttpClient } from '../http/client.js';
import { UnifiApiError } from '../http/errors.js';
import { legacyEnvelope, sysInfoSchema } from './schemas.js';

export type GuardedApi = 'legacy' | 'v2';

export interface GuardedCall<T> {
  api: GuardedApi;
  ref: string;
  method: HttpMethod;
  /** Relative to the site, e.g. `stat/health`; also what the error names. */
  endpoint: string;
  schema: z.ZodType<T>;
  query?: QueryParams;
  body?: unknown;
}

/**
 * Runs undocumented-API calls and turns "this endpoint is not what it was" into
 * one error naming the endpoint and the console's Network version. Gone means a
 * 404, an HTML or redirect answer, or a body that no longer has a field a tool
 * reads. Auth, rate and server errors pass through unchanged.
 */
export interface EndpointGuard {
  call<T>(call: GuardedCall<T>): Promise<T>;
  /** Network application version for messages, `unknown` when sysinfo cannot be read. */
  networkVersion(ref: string): Promise<string>;
  rememberVersion(ref: string, version: string): void;
}

const SITE_SEGMENT: Record<GuardedApi, string> = { legacy: 's', v2: 'site' };

const NOT_FOUND = 'api.err.NotFound';

/** The console's `meta.msg` on an `rc:'error'` body, whatever the HTTP status. */
function errorMessage(raw: unknown): string | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const meta = (raw as { meta?: unknown }).meta;
  if (!meta || typeof meta !== 'object') return undefined;
  const { rc, msg } = meta as { rc?: unknown; msg?: unknown };
  return rc === 'error' && typeof msg === 'string' ? msg : undefined;
}

/**
 * Gone means the console says so: a 404, an HTML or redirect answer, or
 * `api.err.NotFound` at any status. Other errors (bad input, no site context)
 * are the caller's, not a changed endpoint.
 */
function isGone(error: unknown): boolean {
  if (!(error instanceof UnifiApiError)) return false;
  if (error.kind === 'endpoint-changed') return true;
  if (error.kind !== 'status') return false;
  return error.status === 404 || error.detail === NOT_FOUND;
}

export function createEndpointGuard(client: UnifiHttpClient): EndpointGuard {
  const versions = new Map<string, string>();

  async function networkVersion(ref: string): Promise<string> {
    const known = versions.get(ref);
    if (known) return known;
    try {
      const raw = await client.request(
        'legacy',
        'GET',
        `/s/${encodeURIComponent(ref)}/stat/sysinfo`,
      );
      const version = legacyEnvelope(sysInfoSchema).parse(raw).data[0]?.version;
      if (!version) return 'unknown';
      versions.set(ref, version);
      return version;
    } catch {
      return 'unknown';
    }
  }

  async function gone(call: GuardedCall<unknown>, status?: number): Promise<UnifiApiError> {
    const version = await networkVersion(call.ref);
    const path = `/${SITE_SEGMENT[call.api]}/${encodeURIComponent(call.ref)}/${call.endpoint}`;
    return new UnifiApiError({
      kind: 'endpoint-changed',
      method: call.method,
      path,
      status,
      detail: `${call.endpoint} changed or is gone`,
      message: `the console's legacy endpoint ${call.endpoint} changed or is gone (Network ${version}); update unifi-mcp`,
    });
  }

  async function run<T>(call: GuardedCall<T>): Promise<T> {
    const path = `/${SITE_SEGMENT[call.api]}/${encodeURIComponent(call.ref)}/${call.endpoint}`;
    let raw: unknown;
    try {
      raw = await client.request(call.api, call.method, path, {
        query: call.query,
        body: call.body,
      });
    } catch (error) {
      if (isGone(error)) throw await gone(call, (error as UnifiApiError).status);
      throw error;
    }
    const message = errorMessage(raw);
    if (message === NOT_FOUND) throw await gone(call);
    if (message !== undefined) {
      throw new UnifiApiError({
        kind: 'status',
        method: call.method,
        path,
        detail: message,
      });
    }
    const parsed = call.schema.safeParse(raw);
    if (!parsed.success) throw await gone(call);
    return parsed.data;
  }

  return { call: run, networkVersion, rememberVersion: (ref, v) => void versions.set(ref, v) };
}
