import { fetch as undiciFetch, type Dispatcher } from 'undici';
import type { UnifiMcpConfig } from '../config.js';
import { UnifiApiError } from './errors.js';
import { PinnedCertificateMismatch, createConsoleDispatcher } from './tls.js';

export type Api = 'official' | 'legacy' | 'v2' | 'sitemanager';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type QueryValue = string | number | boolean | undefined | null;
export type QueryParams = Record<string, QueryValue>;

export interface RequestOptions {
  query?: QueryParams;
  body?: unknown;
}

export interface UnifiHttpClient {
  request<T>(
    api: Api,
    method: HttpMethod,
    path: string,
    opts?: RequestOptions,
  ): Promise<T | undefined>;
}

export interface FetchInit {
  method: HttpMethod;
  headers: Record<string, string>;
  body?: string;
  signal: AbortSignal;
  /** Always 'manual': fetch keeps X-API-KEY across a cross-origin redirect. */
  redirect: 'manual';
  dispatcher?: Dispatcher;
}

export interface FetchResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

/** The slice of fetch the client uses; undici's own fetch, so the pinned dispatcher is honoured. */
export type FetchFn = (url: string, init: FetchInit) => Promise<FetchResponse>;

export interface UnifiHttpClientOptions {
  /** Per-request timeout, connection to last body byte. */
  timeoutMs?: number;
  /** Test seam: msw only sees globalThis.fetch. */
  fetch?: FetchFn;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const SITE_MANAGER_URL = 'https://api.ui.com';
const MAX_DETAIL = 200;
const ZBF_NOT_CONFIGURED = 'api.firewall.zone-based-firewall-not-configured';
const ZBF_DISABLED =
  'Zone-Based Firewall is not enabled on this console; turn it on in the UniFi UI (Settings → Policy Engine)';

const BASE_PATHS: Record<Exclude<Api, 'sitemanager'>, string> = {
  official: '/proxy/network/integration',
  legacy: '/proxy/network/api',
  v2: '/proxy/network/v2/api',
};

function truncate(text: string): string {
  const clean = text.trim();
  return clean.length > MAX_DETAIL ? `${clean.slice(0, MAX_DETAIL)}...` : clean;
}

function buildQuery(query: QueryParams | undefined): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    params.append(key, String(value));
  }
  const serialised = params.toString();
  return serialised ? `?${serialised}` : '';
}

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

/** The human-readable part of an error body: official `message`, legacy `meta.msg`, or the raw text. */
function bodyMessage(parsed: unknown, raw: string): string {
  if (parsed && typeof parsed === 'object') {
    const record = parsed as Record<string, unknown>;
    const meta = record.meta as Record<string, unknown> | undefined;
    const message = record.message ?? record.error ?? meta?.msg;
    if (typeof message === 'string' && message.length > 0) return truncate(message);
  }
  return truncate(raw);
}

function statusDetail(api: Api, status: number, raw: string, parsed: unknown): string {
  if (status === 401) {
    return api === 'sitemanager'
      ? 'Site Manager rejected UNIFI_SITE_MANAGER_API_KEY; check the key still exists'
      : 'the console rejected UNIFI_API_KEY; check the key still exists';
  }
  if (status === 403) return "the key's admin lacks the role this needs (writes need a full admin)";
  if (!raw.trim()) return status >= 500 ? 'server error with no response body' : 'no response body';
  return bodyMessage(parsed, raw);
}

function isZbfDisabled(status: number, parsed: unknown): boolean {
  return (
    status === 400 &&
    !!parsed &&
    typeof parsed === 'object' &&
    (parsed as { code?: unknown }).code === ZBF_NOT_CONFIGURED
  );
}

/** Origin only: a redirect target's path or query could carry anything. */
function redirectDetail(location: string | null, requestUrl: string): string {
  if (!location) return 'unexpected redirect';
  try {
    return `unexpected redirect to ${new URL(location, requestUrl).origin}`;
  } catch {
    return 'unexpected redirect';
  }
}

function rootCause(error: unknown): unknown {
  let current = error;
  while (current instanceof Error && current.cause !== undefined) current = current.cause;
  return current;
}

function formatSeconds(ms: number): string {
  return `${ms / 1000} s`;
}

export function createUnifiHttpClient(
  config: UnifiMcpConfig,
  opts: UnifiHttpClientOptions = {},
): UnifiHttpClient {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const doFetch: FetchFn = opts.fetch ?? undiciFetch;
  const { baseUrl, apiKey, tls } = config.console;
  // Only the console is pinned; Site Manager is a public service with a CA-signed certificate.
  const consoleDispatcher = createConsoleDispatcher(tls);
  const secrets = [apiKey, config.siteManagerApiKey].filter((s): s is string => !!s);

  /** Belt and braces: a body that echoes a key back must not carry it into an error. */
  function redact(text: string): string {
    return secrets.reduce((out, secret) => out.split(secret).join('[redacted]'), text);
  }

  function target(api: Api): {
    origin: string;
    prefix: string;
    key: string;
    dispatcher?: Dispatcher;
  } {
    if (api === 'sitemanager') {
      if (!config.siteManagerApiKey) {
        throw new Error('Site Manager is not configured (UNIFI_SITE_MANAGER_API_KEY)');
      }
      return { origin: SITE_MANAGER_URL, prefix: '', key: config.siteManagerApiKey };
    }
    return { origin: baseUrl, prefix: BASE_PATHS[api], key: apiKey, dispatcher: consoleDispatcher };
  }

  async function request<T>(
    api: Api,
    method: HttpMethod,
    path: string,
    ro: RequestOptions = {},
  ): Promise<T | undefined> {
    const { origin, prefix, key, dispatcher } = target(api);
    const fullPath = `${prefix}${path}`;
    const url = `${origin}${fullPath}${buildQuery(ro.query)}`;
    const fail = (kind: UnifiApiError['kind'], detail: string, status?: number) =>
      new UnifiApiError({
        kind,
        method,
        path: fullPath,
        status,
        detail: redact(detail),
        baseUrl: origin,
      });

    const headers: Record<string, string> = { 'X-API-KEY': key, Accept: 'application/json' };
    if (ro.body !== undefined) headers['Content-Type'] = 'application/json';

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const timeoutError = () =>
      fail(
        'timeout',
        `no answer from ${api === 'sitemanager' ? 'Site Manager' : 'the console'} after ${formatSeconds(timeoutMs)}`,
      );

    try {
      let response: FetchResponse;
      let raw: string;
      try {
        response = await doFetch(url, {
          method,
          headers,
          body: ro.body === undefined ? undefined : JSON.stringify(ro.body),
          signal: controller.signal,
          redirect: 'manual',
          dispatcher,
        });
        raw = await response.text();
      } catch (cause) {
        if (timedOut) throw timeoutError();
        const inner = rootCause(cause);
        if (inner instanceof PinnedCertificateMismatch) {
          throw fail('certificate-changed', inner.message);
        }
        throw fail('unreachable', inner instanceof Error ? inner.message : String(inner));
      }

      if (response.status >= 300 && response.status < 400) {
        const detail = redirectDetail(response.headers.get('location'), url);
        throw fail('endpoint-changed', detail, response.status);
      }
      const parsed = raw.trim() ? parseJson(raw) : undefined;
      if (!response.ok) {
        if (isZbfDisabled(response.status, parsed)) {
          throw fail('zbf-disabled', ZBF_DISABLED, response.status);
        }
        throw fail('status', statusDetail(api, response.status, raw, parsed), response.status);
      }
      if (!raw.trim()) return undefined;
      if (parsed === undefined) {
        throw fail(
          'endpoint-changed',
          `response was not valid JSON: ${truncate(raw)}`,
          response.status,
        );
      }
      return parsed as T;
    } finally {
      clearTimeout(timer);
    }
  }

  return { request };
}
