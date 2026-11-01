import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createLegacyApi, type LegacyApi } from '../../src/unifi/legacy.js';
import { liveFixture } from '../fixtures/live.js';
import {
  LEGACY,
  failure,
  htmlNotFound,
  legacyNotFound,
  sysinfoHandler,
  testClient,
  useServer,
  withoutField,
} from './helpers.js';

const server = useServer();
const legacy = (): LegacyApi => createLegacyApi(testClient());
const REF = 'default';
const RANGE = { start: 1, end: 2 };

interface Case {
  name: string;
  /** Console path under /s/default, and the fixture that answers it. */
  endpoint: string;
  fixture: string;
  method?: 'GET' | 'POST';
  /** A field a tool reads; deleting it must read as a changed endpoint. */
  field: string;
  call(api: LegacyApi): Promise<unknown>;
  /** Extra endpoints the call also reads. */
  also?: { endpoint: string; fixture: string }[];
}

const cases: Case[] = [
  {
    name: 'sysinfo',
    endpoint: 'stat/sysinfo',
    fixture: 'legacy-stat-sysinfo',
    field: 'version',
    call: (a) => a.sysinfo(REF),
  },
  {
    name: 'health',
    endpoint: 'stat/health',
    fixture: 'legacy-stat-health',
    field: 'subsystem',
    call: (a) => a.health(REF),
  },
  {
    name: 'stations',
    endpoint: 'stat/sta',
    fixture: 'legacy-stat-sta',
    field: 'mac',
    call: (a) => a.stations(REF),
  },
  {
    name: 'devicesBasic',
    endpoint: 'stat/device-basic',
    fixture: 'legacy-stat-device-basic',
    field: 'model',
    call: (a) => a.devicesBasic(REF),
  },
  {
    name: 'knownClients',
    endpoint: 'rest/user',
    fixture: 'legacy-rest-user',
    field: 'mac',
    call: (a) => a.knownClients(REF),
    also: [{ endpoint: 'stat/sta', fixture: 'legacy-stat-sta' }],
  },
  {
    name: 'portForwards',
    endpoint: 'rest/portforward',
    fixture: 'legacy-rest-portforward',
    field: 'fwd',
    call: (a) => a.portForwards(REF),
  },
  {
    name: 'wlanConf',
    endpoint: 'rest/wlanconf',
    fixture: 'legacy-rest-wlanconf',
    field: 'security',
    call: (a) => a.wlanConf(REF),
  },
  {
    name: 'networkConf',
    endpoint: 'rest/networkconf',
    fixture: 'legacy-rest-networkconf',
    field: 'purpose',
    call: (a) => a.networkConf(REF),
  },
  {
    name: 'settings',
    endpoint: 'rest/setting',
    fixture: 'legacy-rest-setting',
    field: 'key',
    call: (a) => a.settings(REF),
  },
  {
    name: 'rogueAps',
    endpoint: 'stat/rogueap',
    fixture: 'legacy-stat-rogueap',
    field: 'bssid',
    call: (a) => a.rogueAps(REF),
  },
  {
    name: 'report',
    endpoint: 'stat/report/5minutes.site',
    fixture: 'legacy-stat-report-5minutes-site',
    method: 'POST',
    field: 'time',
    call: (a) => a.report(REF, '5minutes', 'site', RANGE, ['num_sta']),
  },
  {
    name: 'stationDpi',
    endpoint: 'stat/stadpi',
    fixture: 'legacy-stat-sitedpi',
    method: 'POST',
    field: 'x',
    call: (a) => a.stationDpi(REF, ['02:00:00:00:00:05']),
  },
  {
    name: 'siteDpi',
    endpoint: 'stat/sitedpi',
    fixture: 'legacy-stat-sitedpi',
    field: 'x',
    call: (a) => a.siteDpi(REF),
  },
];

function serve(c: Case, body: unknown) {
  const handler = c.method === 'POST' ? http.post : http.get;
  server.use(handler(`${LEGACY}/${c.endpoint}`, () => HttpResponse.json(body as never)));
  for (const extra of c.also ?? []) {
    server.use(
      http.get(`${LEGACY}/${extra.endpoint}`, () =>
        HttpResponse.json(liveFixture(extra.fixture) as never),
      ),
    );
  }
}

function serveRaw(c: Case, respond: () => Response) {
  const handler = c.method === 'POST' ? http.post : http.get;
  server.use(handler(`${LEGACY}/${c.endpoint}`, respond));
  for (const extra of c.also ?? []) {
    server.use(
      http.get(`${LEGACY}/${extra.endpoint}`, () =>
        HttpResponse.json(liveFixture(extra.fixture) as never),
      ),
    );
  }
}

describe('legacy API parses the live fixtures', () => {
  for (const c of cases) {
    it(`${c.name} returns the fixture's data`, async () => {
      serve(c, liveFixture(c.fixture));
      const result = await c.call(legacy());
      const rows = (liveFixture(c.fixture) as { data: unknown[] }).data;
      if (c.name === 'sysinfo') expect(result).toMatchObject({ version: '10.6.109' });
      else expect(result).toHaveLength(rows.length);
    });
  }

  it('sysinfo returns the console name and version', async () => {
    server.use(sysinfoHandler());
    const info = await legacy().sysinfo(REF);
    expect(info).toMatchObject({ name: 'Gateway CGU', version: '10.6.109' });
  });
});

describe('legacy API maps rows for tools', () => {
  it('portForwards renames the console fields', async () => {
    server.use(
      http.get(`${LEGACY}/rest/portforward`, () =>
        HttpResponse.json(liveFixture('legacy-rest-portforward') as never),
      ),
    );
    const [first] = await legacy().portForwards(REF);
    expect(first).toEqual({
      id: '69382fa41d4c99459c112d5a',
      name: 'Synology',
      enabled: true,
      fwd: '192.168.10.3',
      dstPort: '61119',
      fwdPort: '6690',
      proto: 'tcp_udp',
      src: 'any',
    });
  });

  it('knownClients joins rest/user with the live address and network from stat/sta', async () => {
    server.use(
      http.get(`${LEGACY}/rest/user`, () =>
        HttpResponse.json({
          meta: { rc: 'ok' },
          data: [
            {
              _id: 'u1',
              mac: 'aa:01',
              hostname: 'laptop',
              first_seen: 10,
              last_seen: 20,
              last_ip: '10.0.0.9',
              last_connection_network_id: 'old',
            },
            { _id: 'u2', mac: 'aa:02', name: 'Printer', hostname: 'hp', blocked: true },
            { _id: 'u3', mac: 'aa:03' },
          ],
        }),
      ),
      http.get(`${LEGACY}/stat/sta`, () =>
        HttpResponse.json({
          meta: { rc: 'ok' },
          data: [
            { mac: 'aa:01', is_wired: false, ip: '10.0.0.5', network_id: 'net-1', last_seen: 30 },
          ],
        }),
      ),
    );
    expect(await legacy().knownClients(REF)).toEqual([
      {
        id: 'u1',
        mac: 'aa:01',
        ip: '10.0.0.5',
        name: 'laptop',
        networkId: 'net-1',
        blocked: false,
        firstSeen: 10,
        lastSeen: 30,
      },
      {
        id: 'u2',
        mac: 'aa:02',
        ip: undefined,
        name: 'Printer',
        networkId: undefined,
        blocked: true,
        firstSeen: undefined,
        lastSeen: undefined,
      },
      {
        id: 'u3',
        mac: 'aa:03',
        ip: undefined,
        name: 'aa:03',
        networkId: undefined,
        blocked: false,
        firstSeen: undefined,
        lastSeen: undefined,
      },
    ]);
  });

  it('report posts the attrs and range in ms and keeps the requested attributes', async () => {
    let body: unknown;
    server.use(
      http.post(`${LEGACY}/stat/report/hourly.gw`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(liveFixture('legacy-stat-report-hourly-gw') as never);
      }),
    );
    const rows = await legacy().report(REF, 'hourly', 'gw', { start: 5, end: 9 }, ['cpu', 'mem']);
    expect(body).toEqual({ attrs: ['cpu', 'mem'], start: 5, end: 9 });
    expect(rows[0]).toMatchObject({ cpu: expect.any(Number), time: expect.any(Number) });
  });

  it('a wireless setting never carries the passphrase', async () => {
    server.use(
      http.get(`${LEGACY}/rest/wlanconf`, () =>
        HttpResponse.json(liveFixture('legacy-rest-wlanconf') as never),
      ),
    );
    const rows = await legacy().wlanConf(REF);
    expect(JSON.stringify(rows)).not.toContain('x_passphrase');
  });
});

describe('legacy API reports a changed endpoint', () => {
  for (const c of cases) {
    // sysinfo is where the version comes from, so when it is the broken one there is none.
    const version = c.name === 'sysinfo' ? 'unknown' : '10.6.109';
    const expected = `the console's legacy endpoint ${c.endpoint} changed or is gone (Network ${version}); update unifi-mcp`;
    const serveVersion = () => c.name === 'sysinfo' || server.use(sysinfoHandler());

    it(`${c.name}: HTML 404 page`, async () => {
      serveRaw(c, htmlNotFound);
      serveVersion();
      const error = await failure(c.call(legacy()));
      expect(error.kind).toBe('endpoint-changed');
      expect(error.message).toBe(expected);
    });

    it(`${c.name}: api.err.NotFound`, async () => {
      serveRaw(c, legacyNotFound);
      serveVersion();
      const error = await failure(c.call(legacy()));
      expect(error.kind).toBe('endpoint-changed');
      expect(error.message).toBe(expected);
    });

    if (c.field === 'x') continue; // the DPI fixtures have no fields to delete
    it(`${c.name}: a used field (${c.field}) is gone`, async () => {
      serve(c, withoutField(c.fixture, c.field));
      serveVersion();
      const error = await failure(c.call(legacy()));
      expect(error.kind).toBe('endpoint-changed');
      expect(error.message).toBe(expected);
    });
  }

  it('says the version is unknown when sysinfo fails too', async () => {
    server.use(
      http.get(`${LEGACY}/stat/health`, htmlNotFound),
      http.get(`${LEGACY}/stat/sysinfo`, htmlNotFound),
    );
    const error = await failure(legacy().health(REF));
    expect(error.message).toBe(
      "the console's legacy endpoint stat/health changed or is gone (Network unknown); update unifi-mcp",
    );
  });

  it('reads the version once', async () => {
    let reads = 0;
    server.use(
      http.get(`${LEGACY}/stat/health`, htmlNotFound),
      http.get(`${LEGACY}/stat/sta`, htmlNotFound),
      http.get(`${LEGACY}/stat/sysinfo`, () => {
        reads++;
        return HttpResponse.json(liveFixture('legacy-stat-sysinfo') as never);
      }),
    );
    const api = legacy();
    await failure(api.health(REF));
    await failure(api.stations(REF));
    expect(reads).toBe(1);
  });

  it('leaves other failures alone: 401 stays a status error', async () => {
    server.use(http.get(`${LEGACY}/stat/health`, () => HttpResponse.json({}, { status: 401 })));
    const error = await failure(legacy().health(REF));
    expect(error.kind).toBe('status');
    expect(error.status).toBe(401);
  });
});
