import { HttpResponse, http } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, expect } from 'vitest';
import type { UnifiMcpConfig } from '../../src/config.js';
import { createUnifiHttpClient, type FetchFn } from '../../src/http/client.js';
import { UnifiApiError } from '../../src/http/errors.js';
import { liveFixture } from '../fixtures/live.js';

export const BASE = 'https://console.test';
export const SITE_ID = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
export const LEGACY = `${BASE}/proxy/network/api/s/default`;
export const V2 = `${BASE}/proxy/network/v2/api/site/default`;
export const OFFICIAL = `${BASE}/proxy/network/integration/v1`;

// msw intercepts globalThis.fetch only; see test/http/client.test.ts.
const viaMsw: FetchFn = (url, init) =>
  globalThis.fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    signal: init.signal,
    redirect: init.redirect,
  });

export function testConfig(overrides: Partial<UnifiMcpConfig> = {}): UnifiMcpConfig {
  return {
    console: {
      baseUrl: BASE,
      apiKey: 'console-key',
      tls: { fingerprint: 'AB:'.repeat(31) + 'CD' },
    },
    siteManagerApiKey: 'sm-key',
    readOnly: false,
    protectedNetworks: [],
    transport: 'stdio',
    port: 3000,
    ...overrides,
  };
}

export function testClient(overrides: Partial<UnifiMcpConfig> = {}) {
  return createUnifiHttpClient(testConfig(overrides), { fetch: viaMsw });
}

/** Starts one msw server for the file's tests and returns it. */
export function useServer() {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());
  return server;
}

export const HTML_404 =
  '<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title></head>' +
  '<body><h1>HTTP Status 404 – Not Found</h1></body></html>';

export function htmlNotFound(): Response {
  return new HttpResponse(HTML_404, { status: 404, headers: { 'Content-Type': 'text/html' } });
}

export function legacyNotFound(): Response {
  return HttpResponse.json({ meta: { rc: 'error', msg: 'api.err.NotFound' }, data: [] });
}

/** A fixture with a field removed from its first row. */
export function withoutField(name: string, field: string): unknown {
  const copy = structuredClone(liveFixture(name)) as { data: Record<string, unknown>[] };
  expect(copy.data[0]).toHaveProperty(field);
  delete copy.data[0]![field];
  return copy;
}

export function sysinfoHandler() {
  return http.get(`${LEGACY}/stat/sysinfo`, () =>
    HttpResponse.json(liveFixture('legacy-stat-sysinfo') as never),
  );
}

export async function failure(promise: Promise<unknown>): Promise<UnifiApiError> {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(UnifiApiError);
  return error as UnifiApiError;
}
