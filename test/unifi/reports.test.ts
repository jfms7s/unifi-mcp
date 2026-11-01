import { describe, expect, it } from 'vitest';
import { UnifiApiError } from '../../src/http/errors.js';
import { downsample } from '../../src/unifi/reports.js';
import { createReadTools } from '../../src/unifi/read-tools.js';
import { FIXTURE_NOW, caller, readDeps } from './fixtures.js';

function setup(opts: Parameters<typeof readDeps>[0] = {}) {
  const deps = readDeps(opts);
  const tools = createReadTools(deps);
  return { deps, tools, call: caller(tools) };
}

interface Report {
  scope: string;
  interval: string;
  points: Array<{ time: string; bytes?: number; latencyMs?: number; clients?: number }>;
  downsampled?: { from: number; to: number };
  target?: { name: string };
}

interface Apps {
  scope: string;
  apps: Array<{ name: string; category?: string; bytes: number; rxBytes: number; txBytes: number }>;
  categories: Array<{ name: string; bytes: number }>;
  note?: string;
  ambiguous?: boolean;
}

describe('downsample', () => {
  const series = Array.from({ length: 288 }, (_, i) => ({
    time: i * 300_000,
    bytes: i,
    label: 'x',
  }));

  it('keeps 200 points out of 288 with the first and last unchanged', () => {
    const out = downsample(series, 200);
    expect(out).toHaveLength(200);
    expect(out[0]).toEqual(series[0]);
    expect(out[199]).toEqual(series[287]);
  });

  it('averages the numeric fields of each bucket and keeps the series in time order', () => {
    const out = downsample(
      [
        { time: 0, v: 1 },
        { time: 10, v: 2 },
        { time: 20, v: 4 },
        { time: 30, v: 6 },
        { time: 40, v: 9 },
      ],
      3,
    );
    expect(out).toEqual([
      { time: 0, v: 1 },
      { time: 20, v: 4 },
      { time: 40, v: 9 },
    ]);
    const times = downsample(series, 50).map((p) => p.time);
    expect(times).toEqual([...times].sort((a, b) => a - b));
  });

  it('averages only the points that carry a field', () => {
    const out = downsample(
      [{ time: 0, a: 1 }, { time: 10, a: 5 }, { time: 20 }, { time: 30, a: 7 }] as Array<{
        time: number;
        a?: number;
      }>,
      3,
    );
    expect(out[1]).toEqual({ time: 15, a: 5 });
  });

  it('keeps a field the first point of a bucket lacks', () => {
    const out = downsample(
      [
        { time: 0 },
        { time: 10 },
        { time: 20, latency: 4 },
        { time: 30, latency: 8 },
        { time: 40 },
      ] as Array<{ time: number; latency?: number }>,
      3,
    );
    expect(out[1]?.latency).toBe(6);
  });

  it('returns a short series untouched and rejects a cap below two points', () => {
    expect(downsample(series.slice(0, 5), 200)).toEqual(series.slice(0, 5));
    expect(downsample([], 200)).toEqual([]);
    expect(() => downsample(series, 1)).toThrow(/at least 2/);
  });
});

describe('unifi_traffic_report', () => {
  it('returns at most 200 points of the gateway report with bytes and latency', async () => {
    const { call } = setup();
    const r = (await call('unifi_traffic_report', {
      scope: 'gateway',
      interval: '5minutes',
    })) as Report;
    expect(r.points.length).toBeLessThanOrEqual(200);
    expect(r.points.length).toBeGreaterThan(100);
    expect(r.downsampled).toEqual({ from: 288, to: r.points.length });
    expect(r.points[0]).toMatchObject({ bytes: expect.any(Number), latencyMs: expect.any(Number) });
    expect(r.points[0]?.time).toBe(new Date(1793446200000).toISOString());
    expect(r.points.at(-1)?.time).toBe(new Date(1793532300000).toISOString());
  });

  it('picks an interval from the range when none is given', async () => {
    const { call } = setup();
    expect(((await call('unifi_traffic_report', { scope: 'site' })) as Report).interval).toBe(
      '5minutes',
    );
    expect(
      ((await call('unifi_traffic_report', { scope: 'site', since: '7d' })) as Report).interval,
    ).toBe('hourly');
    expect(
      ((await call('unifi_traffic_report', { scope: 'site', since: '60d' })) as Report).interval,
    ).toBe('daily');
  });

  it('reports site client counts and combined WAN bytes', async () => {
    const { call } = setup();
    const r = (await call('unifi_traffic_report', { scope: 'site', interval: 'hourly' })) as Report;
    expect(r.points[0]).toMatchObject({ bytes: expect.any(Number), clients: expect.any(Number) });
    expect(r.downsampled).toBeUndefined();
  });

  it('asks the console for the scope, interval and range it was given', async () => {
    const { deps, call } = setup();
    await call('unifi_traffic_report', { scope: 'site', interval: 'daily', since: '2d' });
    expect(deps.console.calls).toContain('POST /s/default/stat/report/daily.site');
  });

  it('needs a device for an AP report and reports that AP', async () => {
    const { call } = setup();
    await expect(call('unifi_traffic_report', { scope: 'ap' })).rejects.toThrow(/needs a device/);
    const r = (await call('unifi_traffic_report', {
      scope: 'ap',
      device: '02:00:00:00:00:03',
    })) as Report;
    expect(r.target).toBeDefined();
    expect(r.points[0]).toMatchObject({ bytes: expect.any(Number), clients: expect.any(Number) });
  });

  it('needs a client for a client report and reports that client only', async () => {
    const { call } = setup();
    await expect(call('unifi_traffic_report', { scope: 'client' })).rejects.toThrow(
      /needs a client/,
    );
    const r = (await call('unifi_traffic_report', {
      scope: 'client',
      client: '02:00:00:00:00:8f',
      interval: 'hourly',
    })) as Report;
    expect(r.points.length).toBeGreaterThan(0);
    expect(r.points[0]).toMatchObject({ bytes: expect.any(Number) });
  });

  it('says so when the device or client is unknown', async () => {
    const { call } = setup();
    await expect(
      call('unifi_traffic_report', { scope: 'ap', device: 'no-such-ap' }),
    ).rejects.toThrow(/No device/);
    await expect(
      call('unifi_traffic_report', { scope: 'client', client: 'no-such' }),
    ).rejects.toThrow(/No client/);
  });

  it.each(['site', 'client'])(
    'rejects a device for a %s report instead of ignoring it',
    async (scope) => {
      const { call } = setup();
      await expect(
        call('unifi_traffic_report', { scope, device: 'Gateway CGU', client: '02:00:00:00:00:8f' }),
      ).rejects.toThrow(`device is only for scope ap or gateway, not ${scope}`);
    },
  );

  it.each(['site', 'ap', 'gateway'])(
    'rejects a client for a %s report instead of ignoring it',
    async (scope) => {
      const { call } = setup();
      await expect(
        call('unifi_traffic_report', {
          scope,
          client: '02:00:00:00:00:8f',
          ...(scope === 'ap' ? { device: 'device-3' } : {}),
        }),
      ).rejects.toThrow(`client is only for scope client, not ${scope}`);
    },
  );

  it('an AP report on a device that is not an AP is refused, naming the APs', async () => {
    const { call } = setup();
    await expect(call('unifi_traffic_report', { scope: 'ap', device: 'device-2' })).rejects.toThrow(
      'device-2 is not an access point; the access points are: device-3',
    );
    const r = (await call('unifi_traffic_report', { scope: 'ap', device: 'device-3' })) as Report;
    expect(r.target).toEqual({ name: 'device-3' });
  });

  it('a client report passes on the note when the official client list failed', async () => {
    const { deps, call } = setup();
    deps.official.listClients = async () => {
      throw new UnifiApiError({
        kind: 'timeout',
        method: 'GET',
        path: '/clients',
        detail: 'official API timed out',
      });
    };
    const r = (await call('unifi_traffic_report', {
      scope: 'client',
      client: '02:00:00:00:00:8f',
      interval: 'hourly',
    })) as Report & { note?: string };
    expect(r.points.length).toBeGreaterThan(0);
    expect(r.note).toMatch(/official client list didn't answer/);
    const site = (await call('unifi_traffic_report', { scope: 'site' })) as { note?: string };
    expect(site.note).toBeUndefined();
  });

  describe('with two gateways', () => {
    function twoGateways() {
      const ctx = setup();
      const list = ctx.deps.official.listDevices.bind(ctx.deps.official);
      ctx.deps.official.listDevices = async (siteId) => {
        const devices = await list(siteId);
        const gw = devices.find((d) => d.name === 'Gateway CGU')!;
        return [
          ...devices,
          {
            ...gw,
            id: 'second-gateway',
            macAddress: '02:00:00:00:00:f0',
            name: 'Gateway Two',
            ipAddress: '192.168.1.163',
          },
        ];
      };
      return ctx;
    }

    it('a gateway report needs a device, and the error lists the gateways', async () => {
      const { call } = twoGateways();
      await expect(call('unifi_traffic_report', { scope: 'gateway' })).rejects.toThrow(
        'This site has 2 gateways; pick one with device: Gateway CGU, Gateway Two',
      );
    });

    it('filters the report by the chosen gateway', async () => {
      const { call } = twoGateways();
      const mine = (await call('unifi_traffic_report', {
        scope: 'gateway',
        device: 'Gateway CGU',
        interval: 'hourly',
      })) as Report;
      expect(mine.target).toEqual({ name: 'Gateway CGU' });
      expect(mine.points.length).toBeGreaterThan(0);
      const other = (await call('unifi_traffic_report', {
        scope: 'gateway',
        device: 'Gateway Two',
        interval: 'hourly',
      })) as Report;
      expect(other.points).toEqual([]);
    });
  });

  it('a gateway report on a device that is not a gateway is refused', async () => {
    const { call } = setup();
    await expect(
      call('unifi_traffic_report', { scope: 'gateway', device: 'device-2' }),
    ).rejects.toThrow('device-2 is not a gateway');
  });

  it('keeps only points inside the range', async () => {
    const { call } = setup();
    const r = (await call('unifi_traffic_report', {
      scope: 'gateway',
      interval: '5minutes',
      since: '1h',
    })) as Report;
    expect(r.points.length).toBeLessThanOrEqual(13);
    expect(Date.parse(r.points[0]!.time)).toBeGreaterThanOrEqual(FIXTURE_NOW - 3_600_000);
  });
});

// The live console returned no DPI rows (2026-11-01), so these rows are synthetic.
// Shape: app = (category << 16) | application id.
const QQ = (4 << 16) | 4;
describe('unifi_top_apps', () => {
  it('names applications and categories from the DPI catalogue, biggest first', async () => {
    const { deps, call } = setup();
    deps.legacy.siteDpi = async () => [
      {
        by_app: [
          { app: 3, cat: 0, rx_bytes: 100, tx_bytes: 50 },
          { app: QQ, cat: 4, rx_bytes: 1000, tx_bytes: 500 },
          { app: QQ, cat: 4, rx_bytes: 10, tx_bytes: 5 },
        ],
        by_cat: [
          { cat: 0, rx_bytes: 100, tx_bytes: 50 },
          { cat: 4, rx_bytes: 1010, tx_bytes: 505 },
        ],
      },
    ];
    const r = (await call('unifi_top_apps')) as Apps;
    expect(r.scope).toBe('site');
    expect(r.apps[0]).toMatchObject({
      name: 'QQ/TM',
      category: 'Media streaming services',
      bytes: 1515,
      rxBytes: 1010,
      txBytes: 505,
    });
    expect(r.apps[1]).toMatchObject({ name: 'ICQ', category: 'Instant messengers', bytes: 150 });
    expect(r.categories.map((c) => c.name)).toEqual([
      'Media streaming services',
      'Instant messengers',
    ]);
  });

  it('shows an id the catalogue lacks as "app <id>" and keeps the top 10', async () => {
    const { deps, call } = setup();
    deps.legacy.siteDpi = async () => [
      {
        by_app: Array.from({ length: 15 }, (_, i) => ({
          app: 900_000 + i,
          cat: 99,
          rx_bytes: i + 1,
          tx_bytes: 0,
        })),
      },
    ];
    const r = (await call('unifi_top_apps')) as Apps;
    expect(r.apps).toHaveLength(10);
    expect(r.apps[0]?.name).toBe('app 900014');
    expect(r.categories).toEqual([]);
  });

  it('tries the raw id first, then the decoded one, and merges only what names the same entry', async () => {
    const { deps, call } = setup();
    deps.legacy.siteDpi = async () => [
      {
        by_app: [
          { app: 3, cat: 0, rx_bytes: 10, tx_bytes: 0 },
          { app: (4 << 16) | 3, cat: 4, rx_bytes: 5, tx_bytes: 0 },
          { app: 70_000, cat: 9, rx_bytes: 2, tx_bytes: 0 },
          { app: 70_000 + 65_536, cat: 9, rx_bytes: 1, tx_bytes: 0 },
        ],
      },
    ];
    const r = (await call('unifi_top_apps')) as Apps;
    expect(r.apps.map((a) => [a.name, a.bytes])).toEqual([
      ['ICQ', 15],
      ['app 70000', 2],
      ['app 135536', 1],
    ]);
  });

  it('falls back to app/category ids with a note when the DPI catalogue is unavailable', async () => {
    const { deps, call } = setup();
    deps.official.listDpiApps = async () => {
      throw new Error('catalogue down');
    };
    deps.legacy.siteDpi = async () => [
      {
        by_app: [{ app: 3, cat: 0, rx_bytes: 1, tx_bytes: 1 }],
        by_cat: [{ cat: 0, rx_bytes: 1, tx_bytes: 1 }],
      },
    ];
    const r = (await call('unifi_top_apps')) as Apps;
    expect(r.apps[0]?.name).toBe('app 3');
    expect(r.categories[0]?.name).toBe('Instant messengers');
    expect(r.note).toMatch(/catalogue/i);
  });

  it('asks stat/stadpi for one client and reads only that client', async () => {
    const { deps, call } = setup();
    const asked: Array<string[] | undefined> = [];
    deps.legacy.stationDpi = async (_ref, macs) => {
      asked.push(macs);
      return [
        { mac: '02:00:00:00:00:8f', by_app: [{ app: 3, cat: 0, rx_bytes: 7, tx_bytes: 1 }] },
        { mac: '02:00:00:00:00:99', by_app: [{ app: QQ, cat: 4, rx_bytes: 999, tx_bytes: 1 }] },
      ];
    };
    const r = (await call('unifi_top_apps', { client: '02:00:00:00:00:8f' })) as Apps;
    expect(asked).toEqual([['02:00:00:00:00:8f']]);
    expect(r.scope).toBe('client');
    expect(r.apps.map((a) => a.name)).toEqual(['ICQ']);
  });

  it('says why when the console has no DPI rows, with the real fixtures', async () => {
    const { call } = setup();
    const r = (await call('unifi_top_apps')) as Apps;
    expect(r.apps).toEqual([]);
    expect(r.note).toMatch(/no DPI data/i);
  });

  it("a client's top apps pass on the note when the official client list failed", async () => {
    const { deps, call } = setup();
    deps.official.listClients = async () => {
      throw new UnifiApiError({
        kind: 'timeout',
        method: 'GET',
        path: '/clients',
        detail: 'official API timed out',
      });
    };
    const r = (await call('unifi_top_apps', { client: '02:00:00:00:00:8f' })) as Apps;
    expect(r.scope).toBe('client');
    expect(r.note).toMatch(/no DPI data.*; the official client list didn't answer/i);
    const ok = (await setup().call('unifi_top_apps', { client: '02:00:00:00:00:8f' })) as Apps;
    expect(ok.note ?? '').not.toMatch(/official client list/);
  });

  it('refuses to guess between clients', async () => {
    const { call } = setup();
    const r = (await call('unifi_top_apps', { client: 'client-' })) as Apps;
    expect(r.ambiguous).toBe(true);
  });
});

describe('unifi_isp_metrics', () => {
  it('is registered only with Site Manager and summarises ISP latency, loss and uptime', async () => {
    const without = setup({ sitemanager: false });
    expect(without.tools.map((t) => t.name)).not.toContain('unifi_isp_metrics');
    const { call } = setup();
    const r = (await call('unifi_isp_metrics')) as {
      interval: string;
      series: Array<Record<string, unknown>>;
    };
    expect(r.interval).toBe('5m');
    expect(r.series[0]).toMatchObject({
      avgLatencyMs: expect.any(Number),
      uptimePct: expect.any(Number),
    });
  });

  it('uses hourly data for a range over a day', async () => {
    const { call } = setup();
    expect(
      ((await call('unifi_isp_metrics', { since: '7d' })) as { interval: string }).interval,
    ).toBe('1h');
  });
});
