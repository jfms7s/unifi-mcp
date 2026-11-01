import { HttpResponse, delay, http } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { UnifiMcpConfig } from '../../src/config.js';
import { createUnifiHttpClient, type FetchFn } from '../../src/http/client.js';
import { UnifiApiError } from '../../src/http/errors.js';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const KEY = 'console-secret-key';
const SM_KEY = 'site-manager-secret-key';
const BASE = 'https://console.test';
const FP = 'AB:'.repeat(31) + 'CD';

// msw intercepts globalThis.fetch, not undici's own fetch. The pinned
// dispatcher is undici 7's and means nothing to Node's bundled fetch, so it is
// dropped here; test/http/tls.test.ts covers it against a real TLS server.
const viaMsw: FetchFn = (url, init) =>
  globalThis.fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    signal: init.signal,
  });

function config(overrides: Partial<UnifiMcpConfig> = {}): UnifiMcpConfig {
  return {
    console: { baseUrl: BASE, apiKey: KEY, tls: { fingerprint: FP } },
    siteManagerApiKey: SM_KEY,
    readOnly: false,
    protectedNetworks: [],
    transport: 'stdio',
    port: 3000,
    ...overrides,
  };
}

const client = createUnifiHttpClient(config(), { fetch: viaMsw });

async function failure(promise: Promise<unknown>): Promise<UnifiApiError> {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(UnifiApiError);
  return error as UnifiApiError;
}

describe('createUnifiHttpClient', () => {
  it('sends X-API-KEY and never the key in errors', async () => {
    let sent: string | null = null;
    server.use(
      http.get(`${BASE}/proxy/network/integration/v1/sites`, ({ request }) => {
        sent = request.headers.get('X-API-KEY');
        // A console that echoes the key back must not leak it through the error.
        return HttpResponse.text(`internal error for key ${sent}`, { status: 500 });
      }),
    );
    const error = await failure(client.request('official', 'GET', '/v1/sites'));
    expect(sent).toBe(KEY);
    expect(error.kind).toBe('status');
    expect(error.status).toBe(500);
    expect(String(error)).not.toContain(KEY);
    expect(JSON.stringify(error)).not.toContain(KEY);
  });

  it.each([
    ['official', `${BASE}/proxy/network/integration/v1/sites`],
    ['legacy', `${BASE}/proxy/network/api/v1/sites`],
    ['v2', `${BASE}/proxy/network/v2/api/v1/sites`],
  ] as const)('maps %s to its base path', async (api, url) => {
    server.use(http.get(url, () => HttpResponse.json({ ok: api })));
    await expect(client.request(api, 'GET', '/v1/sites')).resolves.toEqual({ ok: api });
  });

  it('sends the Site Manager key to api.ui.com', async () => {
    let sent: string | null = null;
    server.use(
      http.get('https://api.ui.com/v1/hosts', ({ request }) => {
        sent = request.headers.get('X-API-KEY');
        return HttpResponse.json({ data: [] });
      }),
    );
    await expect(client.request('sitemanager', 'GET', '/v1/hosts')).resolves.toEqual({ data: [] });
    expect(sent).toBe(SM_KEY);
  });

  it('refuses Site Manager calls without a key', async () => {
    const bare = createUnifiHttpClient(config({ siteManagerApiKey: undefined }), { fetch: viaMsw });
    await expect(bare.request('sitemanager', 'GET', '/v1/hosts')).rejects.toThrow(
      'Site Manager is not configured (UNIFI_SITE_MANAGER_API_KEY)',
    );
  });

  it('serialises query parameters and drops undefined and null', async () => {
    let url: URL | undefined;
    server.use(
      http.get(`${BASE}/proxy/network/integration/v1/sites/s1/clients`, ({ request }) => {
        url = new URL(request.url);
        return HttpResponse.json({ data: [] });
      }),
    );
    await client.request('official', 'GET', '/v1/sites/s1/clients', {
      query: { offset: 0, limit: 200, filter: undefined, other: null },
    });
    expect(url?.searchParams.get('offset')).toBe('0');
    expect(url?.searchParams.get('limit')).toBe('200');
    expect(url?.searchParams.has('filter')).toBe(false);
    expect(url?.searchParams.has('other')).toBe(false);
  });

  it('sends a JSON body with its content type', async () => {
    let seen: { body: unknown; type: string | null } | undefined;
    server.use(
      http.post(
        `${BASE}/proxy/network/api/s/default/stat/report/daily.site`,
        async ({ request }) => {
          seen = { body: await request.json(), type: request.headers.get('Content-Type') };
          return HttpResponse.json({ meta: { rc: 'ok' }, data: [] });
        },
      ),
    );
    await client.request('legacy', 'POST', '/s/default/stat/report/daily.site', {
      body: { attrs: ['bytes'] },
    });
    expect(seen).toEqual({ body: { attrs: ['bytes'] }, type: 'application/json' });
  });

  it('returns undefined for 204 and empty bodies', async () => {
    server.use(
      http.delete(
        `${BASE}/proxy/network/integration/v1/x`,
        () => new HttpResponse(null, { status: 204 }),
      ),
      http.put(
        `${BASE}/proxy/network/integration/v1/x`,
        () => new HttpResponse('', { status: 200 }),
      ),
    );
    await expect(client.request('official', 'DELETE', '/v1/x')).resolves.toBeUndefined();
    await expect(client.request('official', 'PUT', '/v1/x', { body: {} })).resolves.toBeUndefined();
  });

  it('401 explains the key', async () => {
    server.use(
      http.get(
        `${BASE}/proxy/network/integration/v1/sites`,
        () => new HttpResponse(null, { status: 401 }),
      ),
    );
    const error = await failure(client.request('official', 'GET', '/v1/sites'));
    expect(error.kind).toBe('status');
    expect(error.status).toBe(401);
    expect(error.detail).toBe('the console rejected UNIFI_API_KEY; check the key still exists');
  });

  it("403 explains the admin's role", async () => {
    server.use(
      http.patch(`${BASE}/proxy/network/integration/v1/x`, () =>
        HttpResponse.json({ message: 'no' }, { status: 403 }),
      ),
    );
    const error = await failure(client.request('official', 'PATCH', '/v1/x', { body: {} }));
    expect(error.detail).toBe(
      "the key's admin lacks the role this needs (writes need a full admin)",
    );
  });

  it('times out with kind timeout', async () => {
    server.use(
      http.get(`${BASE}/proxy/network/integration/v1/sites`, async () => {
        await delay('infinite');
        return HttpResponse.json({});
      }),
    );
    const quick = createUnifiHttpClient(config(), { fetch: viaMsw, timeoutMs: 50 });
    const error = await failure(quick.request('official', 'GET', '/v1/sites'));
    expect(error.kind).toBe('timeout');
    expect(error.detail).toBe('no answer from the console after 0.05 s');
  });

  it('says 15 s by default', async () => {
    let abortedAfterMs = 0;
    const capture: FetchFn = (_url, init) =>
      new Promise((_resolve, reject) => {
        const started = Date.now();
        init.signal.addEventListener('abort', () => {
          abortedAfterMs = Date.now() - started;
          reject(init.signal.reason as Error);
        });
      });
    vi.useFakeTimers();
    try {
      const pending = createUnifiHttpClient(config(), { fetch: capture })
        .request('official', 'GET', '/v1/sites')
        .catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(15_000);
      const error = (await pending) as UnifiApiError;
      expect(error.kind).toBe('timeout');
      expect(error.detail).toBe('no answer from the console after 15 s');
      expect(abortedAfterMs).toBe(15_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('turns the ZBF-not-configured 400 into zbf-disabled', async () => {
    server.use(
      http.get(`${BASE}/proxy/network/integration/v1/sites/s1/firewall/zones`, () =>
        HttpResponse.json(
          {
            statusCode: 400,
            statusName: 'BAD_REQUEST',
            code: 'api.firewall.zone-based-firewall-not-configured',
            message: 'Zone Based Firewall is not configured',
            timestamp: '2026-11-01T10:00:00Z',
            requestPath: '/integration/v1/sites/s1/firewall/zones',
            requestId: 'r1',
          },
          { status: 400 },
        ),
      ),
    );
    const error = await failure(client.request('official', 'GET', '/v1/sites/s1/firewall/zones'));
    expect(error.kind).toBe('zbf-disabled');
    expect(error.status).toBe(400);
    expect(error.message).toBe(
      'Zone-Based Firewall is not enabled on this console; turn it on in the UniFi UI (Settings → Policy Engine)',
    );
  });

  it('uses the message of an official error body as the detail', async () => {
    server.use(
      http.get(`${BASE}/proxy/network/integration/v1/sites/s1/devices/d1`, () =>
        HttpResponse.json(
          { statusCode: 404, code: 'api.err.DeviceNotFound', message: 'Device d1 not found' },
          { status: 404 },
        ),
      ),
    );
    const error = await failure(client.request('official', 'GET', '/v1/sites/s1/devices/d1'));
    expect(error.detail).toBe('Device d1 not found');
    expect(error.message).toBe(
      'UniFi returned 404 for GET /proxy/network/integration/v1/sites/s1/devices/d1: Device d1 not found',
    );
  });

  it('uses meta.msg of a legacy error body as the detail', async () => {
    server.use(
      http.get(`${BASE}/proxy/network/api/s/default/stat/sta`, () =>
        HttpResponse.json(
          { meta: { rc: 'error', msg: 'api.err.NoSiteContext' }, data: [] },
          { status: 400 },
        ),
      ),
    );
    const error = await failure(client.request('legacy', 'GET', '/s/default/stat/sta'));
    expect(error.detail).toBe('api.err.NoSiteContext');
  });

  it('calls a 200 that is not JSON an endpoint change', async () => {
    server.use(
      http.get(`${BASE}/proxy/network/api/self`, () =>
        HttpResponse.text('<html>', { status: 200 }),
      ),
    );
    const error = await failure(client.request('legacy', 'GET', '/self'));
    expect(error.kind).toBe('endpoint-changed');
    expect(error.detail).toMatch(/not valid JSON/);
  });

  it('reports a network failure as unreachable', async () => {
    server.use(http.get(`${BASE}/proxy/network/integration/v1/sites`, () => HttpResponse.error()));
    const error = await failure(client.request('official', 'GET', '/v1/sites'));
    expect(error.kind).toBe('unreachable');
    expect(error.message).toMatch(/^Cannot reach UniFi at https:\/\/console\.test for GET/);
  });
});
