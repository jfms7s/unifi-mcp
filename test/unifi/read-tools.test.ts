import { describe, expect, it } from 'vitest';
import { createReadTools } from '../../src/unifi/read-tools.js';
import { FIXTURE_NOW, caller, readDeps, syntheticLog } from './fixtures.js';

function setup(opts: Parameters<typeof readDeps>[0] = {}) {
  const deps = readDeps(opts);
  const tools = createReadTools(deps);
  return { deps, tools, call: caller(tools) };
}

interface Shape {
  console: Record<string, unknown>;
  network: { version: string };
  devices: Record<string, number>;
  clients: Record<string, number>;
  health: Array<{ subsystem: string; status: string }>;
  recentHighEvents: number;
  recentHighEventsNote: string;
}

interface Wan {
  wans: Array<{ name: string }>;
  gateway: Record<string, unknown>;
  internet: Record<string, unknown>;
  ispMetrics: { interval: string; series: Array<Record<string, unknown>> } | Record<string, unknown>;
}

interface Row {
  id: string;
  name: string;
  [key: string]: unknown;
}

describe('registration', () => {
  it('registers the diagnosis tools, all read-only and unifi_ prefixed', () => {
    const { tools } = setup();
    expect(tools.map((t) => t.name)).toEqual([
      'unifi_overview',
      'unifi_list_devices',
      'unifi_get_device',
      'unifi_list_clients',
      'unifi_get_client',
      'unifi_wan_status',
      'unifi_vpn_status',
      'unifi_events',
      'unifi_threat_summary',
      'unifi_posture_audit',
      'unifi_list_firewall',
      'unifi_list_port_forwards',
      'unifi_list_wifi',
      'unifi_list_networks',
      'unifi_audit_log',
      'unifi_traffic_report',
      'unifi_top_apps',
      'unifi_isp_metrics',
      'unifi_list_hosts',
    ]);
    for (const tool of tools) {
      expect(tool.annotations).toEqual({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
    }
  });

  it('leaves out the Site Manager tools when it is not configured', () => {
    const { tools } = setup({ sitemanager: false });
    expect(tools.map((t) => t.name)).not.toContain('unifi_list_hosts');
    expect(tools.map((t) => t.name)).not.toContain('unifi_isp_metrics');
    expect(tools).toHaveLength(17);
  });
});

describe('unifi_overview', () => {
  it('reports the console, the Network version, health and device counts', async () => {
    const { call } = setup();
    const overview = (await call('unifi_overview')) as Shape;
    expect(overview.console).toMatchObject({
      name: 'Gateway CGU',
      model: 'UniFi Cloud Gateway Ultra',
    });
    expect(overview.network.version).toBe('10.6.109');
    expect(overview.health.map((h) => h.subsystem)).toEqual([
      'wlan',
      'wan',
      'www',
      'lan',
      'vpn',
    ]);
    expect(overview.health.find((h) => h.subsystem === 'wan')).toMatchObject({
      status: 'ok',
    });
    expect(overview.devices).toEqual({ total: 4, online: 4, offline: 0, other: 0, upgradable: 0 });
    expect(overview.clients).toEqual({ total: 31, wired: 17, wireless: 14, other: 0 });
  });

  it('counts HIGH and VERY_HIGH events in the 24 h before now', async () => {
    const { call } = setup();
    const overview = (await call('unifi_overview')) as { recentHighEvents: number };
    expect(overview.recentHighEvents).toBe(380);
  });

  it('moves the 24 h window with the injected clock', async () => {
    const { call } = setup({ now: FIXTURE_NOW - 6 * 86_400_000 });
    const overview = (await call('unifi_overview')) as { recentHighEvents: number };
    expect(overview.recentHighEvents).not.toBe(380);
  });

  it('names the devices that are not online', async () => {
    const { deps, call } = setup();
    const devices = await deps.official.listDevices('x');
    deps.official.listDevices = async () => [{ ...devices[2]!, state: 'OFFLINE' }, ...devices];
    const overview = (await call('unifi_overview')) as {
      devices: Record<string, number>;
      offlineDevices: string[];
    };
    expect(overview.devices).toMatchObject({ total: 5, offline: 1 });
    expect(overview.offlineDevices).toEqual([devices[2]!.name]);
  });

  it('counts every HIGH event the log holds for the window', async () => {
    const { call } = setup({ log: syntheticLog(1500) });
    const overview = (await call('unifi_overview')) as { recentHighEvents: number };
    expect(overview.recentHighEvents).toBe(1500);
  });
});

describe('unifi_overview with a log past the ceiling', () => {
  it('calls the count a floor and says how far back it read', async () => {
    const { call } = setup({ log: syntheticLog(21_000) });
    const overview = (await call('unifi_overview')) as Shape;
    expect(overview.recentHighEvents).toBe(20_000);
    expect(overview.recentHighEventsNote).toMatch(/stopped at 20000 events, range only covered back to 20.*floor/);
  });
});

describe('unifi_list_devices / unifi_get_device', () => {
  it('lists each device with firmware, state and load', async () => {
    const { call } = setup();
    const result = (await call('unifi_list_devices')) as { devices: Row[] };
    expect(result.devices).toHaveLength(4);
    expect(result.devices[0]).toMatchObject({
      name: 'Gateway CGU',
      model: 'UCG Ultra',
      state: 'ONLINE',
      firmware: '5.1.34',
      updateAvailable: false,
      cpuPct: 43.7,
      memoryPct: 66.9,
    });
    expect(result.devices[0]).not.toHaveProperty('mac');
  });

  it('summarises each device: uplink, ports up and PoE in use, radios', async () => {
    const { call } = setup();
    const result = (await call('unifi_list_devices')) as { devices: Row[] };
    const byName = (name: string) => result.devices.find((d) => d.name === name);
    expect(byName('Gateway CGU')).toMatchObject({ uplink: 'WAN', ports: { up: 3, total: 5 } });
    expect(byName('Gateway CGU')?.ports).not.toHaveProperty('poeInUse');
    expect(byName('device-2')).toMatchObject({
      uplink: 'Gateway CGU port 1',
      ports: { up: 8, total: 8, poeInUse: 5 },
    });
    expect(byName('device-4')).toMatchObject({
      uplink: 'Gateway CGU port 2',
      ports: { up: 4, total: 10, poeInUse: 1 },
    });
    expect(byName('device-3')).toMatchObject({
      uplink: 'device-4 port 8',
      radios: [
        { band: '2.4 GHz', channel: 11, clients: 9 },
        { band: '5 GHz', channel: 44, clients: 4 },
      ],
    });
    expect(byName('device-3')).not.toHaveProperty('ports');
    expect(JSON.stringify(result)).not.toMatch(/02:00:00/);
  });

  it('an offline device shows where it last hung; a failed stat/device read leaves a note', async () => {
    const { deps, call } = setup();
    const links = await deps.legacy.devices('default');
    const ap = links.find((d) => d.mac === '02:00:00:00:00:03')!;
    deps.legacy.devices = async () => [
      ...links.filter((d) => d !== ap),
      { ...ap, uplinkMac: undefined, uplinkPort: undefined, lastUplinkMac: '02:00:00:00:00:04', lastUplinkPort: 8 },
    ];
    const offline = (await call('unifi_list_devices')) as { devices: Row[] };
    expect(offline.devices.find((d) => d.name === 'device-3')?.uplink).toBe('device-4 port 8 (last seen)');

    deps.legacy.devices = async () => {
      throw new Error('stat/device is gone');
    };
    const bare = (await call('unifi_list_devices')) as { devices: Row[]; note: string };
    expect(bare.devices).toHaveLength(4);
    expect(bare.devices[0]).not.toHaveProperty('uplink');
    expect(bare.note).toMatch(/uplink, port and radio summary unavailable/);
  });

  it('finds a device by name, MAC, IP or id', async () => {
    const { call } = setup();
    for (const device of ['Gateway CGU', '02:00:00:00:00:01', '192.168.1.162']) {
      const found = (await call('unifi_get_device', { device })) as { name: string };
      expect(found.name).toBe('Gateway CGU');
    }
    const byId = (await call('unifi_get_device', {
      device: '0b8af13c-8fc3-3809-96d4-cd4e6e1720c8',
    })) as { name: string };
    expect(byId.name).toBe('Gateway CGU');
  });

  it('adds statistics and the legacy adoption state', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_device', { device: 'Gateway CGU' })) as Row;
    expect(found).toMatchObject({
      mac: '02:00:00:00:00:01',
      uptimeSec: 132293,
      adopted: true,
      type: 'udm',
      uplink: { txRateBps: 303616, rxRateBps: 1227312 },
    });
  });

  it('returns candidates instead of guessing on an ambiguous name', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_device', { device: 'device-' })) as {
      ambiguous: boolean;
      candidates: Row[];
    };
    expect(found.ambiguous).toBe(true);
    expect(found.candidates.map((c) => c.name)).toEqual(['device-2', 'device-3', 'device-4']);
  });

  it('fails clearly when nothing matches', async () => {
    const { call } = setup();
    await expect(call('unifi_get_device', { device: 'nope' })).rejects.toThrow(/No device matches "nope"/);
  });
});

describe('unifi_list_clients', () => {
  it('lists connected clients without raw MACs', async () => {
    const { call } = setup();
    const result = (await call('unifi_list_clients')) as { clients: Row[]; total: number };
    expect(result.total).toBe(31);
    expect(result.clients).toHaveLength(31);
    for (const client of result.clients) {
      expect(client).not.toHaveProperty('mac');
      expect(JSON.stringify(client)).not.toMatch(/02:00:00:00:00:[0-9a-f]{2}/);
    }
    expect(result.clients.find((c) => c.name === 'data-archive')).toMatchObject({
      ip: '192.168.10.3',
      network: 'Default',
      connected: true,
    });
  });

  it('filters by network', async () => {
    const { call } = setup();
    const result = (await call('unifi_list_clients', { network: 'IoT' })) as {
      clients: Row[];
    };
    expect(result.clients.length).toBeGreaterThan(0);
    expect(result.clients.every((c) => c.network === 'IoT')).toBe(true);
  });

  it('filters wired and wireless', async () => {
    const { call } = setup();
    const wireless = (await call('unifi_list_clients', { wired: false })) as { clients: Row[] };
    const wired = (await call('unifi_list_clients', { wired: true })) as { clients: Row[] };
    expect(wireless.clients).toHaveLength(14);
    expect(wired.clients).toHaveLength(17);
    expect(wireless.clients.every((c) => c.wired === false && c.signalDbm !== undefined)).toBe(true);
  });

  it('filters blocked clients, which are not connected', async () => {
    const { deps, call } = setup();
    const known = await deps.legacy.knownClients('default');
    deps.legacy.knownClients = async () => [
      { ...known[0]!, id: 'blocked-1', mac: 'aa:bb:cc:00:00:01', name: 'blocked-one', blocked: true },
      ...known,
    ];
    const result = (await call('unifi_list_clients', { blocked: true })) as {
      clients: Row[];
      total: number;
    };
    expect(result.total).toBe(1);
    expect(result.clients[0]).toMatchObject({ name: 'blocked-one', blocked: true, connected: false });
  });

  it('keeps clients first seen since a span or date', async () => {
    const { call } = setup();
    const all = (await call('unifi_list_clients', { includeOffline: true })) as { total: number };
    const recent = (await call('unifi_list_clients', {
      firstSeenSince: '7d',
      includeOffline: true,
    })) as { total: number; clients: Row[] };
    expect(recent.total).toBeLessThan(all.total);
    expect(recent.total).toBeGreaterThan(0);
    const cutoff = FIXTURE_NOW - 7 * 86_400_000;
    expect(recent.clients.every((c) => Date.parse(c.firstSeen as string) >= cutoff)).toBe(true);
  });

  it('says how many were cut when the list is longer than the limit', async () => {
    const { call } = setup();
    const result = (await call('unifi_list_clients', { includeOffline: true, limit: 50 })) as {
      clients: Row[];
      truncated: { shown: number; total: number };
    };
    expect(result.clients).toHaveLength(50);
    expect(result.truncated).toEqual({ shown: 50, total: 135 });
  });

  it('has no truncated field when nothing was cut', async () => {
    const { call } = setup();
    expect(await call('unifi_list_clients')).not.toHaveProperty('truncated');
  });

  it('refuses a limit above 500', async () => {
    const { call } = setup();
    await expect(call('unifi_list_clients', { limit: 501 })).rejects.toThrow();
  });
});

describe('unifi_get_client', () => {
  it('finds a client by MAC and shows its MAC', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: '02:00:00:00:00:1a' })) as Row;
    expect(found).toMatchObject({ name: 'data-archive', mac: '02:00:00:00:00:1a', connected: true });
  });

  it('finds the same client by MAC, IP, id and name', async () => {
    const { call } = setup();
    const byMac = (await call('unifi_get_client', { client: '02:00:00:00:00:1a' })) as Row;
    for (const client of [byMac.ip, byMac.id, '02:00:00:00:00:1A', '020000000 01a'.replace(' ', '')]) {
      const found = (await call('unifi_get_client', { client })) as Row;
      expect(found.mac).toBe('02:00:00:00:00:1a');
    }
    const byName = (await call('unifi_get_client', { client: 'client-1' })) as Row;
    expect(byName.name).toBe('client-1');
  });

  it('returns both candidates when two clients share a name', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: 'data-archive' })) as {
      ambiguous: boolean;
      candidates: Row[];
    };
    expect(found.ambiguous).toBe(true);
    expect(found).toMatchObject({ message: expect.stringMatching(/id or IP/) });
    expect(found.candidates.map((c) => [c.connected, c.network])).toEqual(
      expect.arrayContaining([
        [true, 'Default'],
        [false, 'pi-cluster'],
      ]),
    );
  });

  it('shows signal and rate for a wireless client', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: 'client-25' })) as Row;
    expect(found).toMatchObject({ wired: false, signalDbm: -66, essid: 'ssid-2', network: 'IoT' });
  });

  it('returns the candidates for an ambiguous name, not a guess', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: 'client-2' })) as {
      ambiguous: boolean;
      candidates: Row[];
    };
    // exact "client-2" exists, so it wins over client-20..29
    expect(found.ambiguous).toBeUndefined();
    const partial = (await call('unifi_get_client', { client: 'ient-2' })) as {
      ambiguous: boolean;
      candidates: Row[];
    };
    expect(partial.ambiguous).toBe(true);
    expect(partial.candidates.length).toBeGreaterThan(1);
    for (const c of partial.candidates) expect(c).not.toHaveProperty('mac');
  });

  it('fails clearly when nothing matches', async () => {
    const { call } = setup();
    await expect(call('unifi_get_client', { client: 'ghost' })).rejects.toThrow(/No client matches "ghost"/);
  });
});

describe('official client join', () => {
  const OFFICIAL_ID = '41b34643-7821-3af9-961a-4fc95ab9f818'; // MAC 02:00:00:00:00:05

  it('shows officialId and access in get_client', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: '02:00:00:00:00:05' })) as Row;
    expect(found).toMatchObject({ officialId: OFFICIAL_ID, access: 'DEFAULT', name: 'client-1' });
  });

  it('finds a client by its official UUID', async () => {
    const { call } = setup();
    const found = (await call('unifi_get_client', { client: OFFICIAL_ID })) as Row;
    expect(found.mac).toBe('02:00:00:00:00:05');
  });

  it('still finds a client with no official match', async () => {
    const { deps, call } = setup();
    deps.official.listClients = async () => [];
    const found = (await call('unifi_get_client', { client: '02:00:00:00:00:05' })) as Row;
    expect(found.name).toBe('client-1');
    expect(found).not.toHaveProperty('officialId');
  });

  it('a failing official client list leaves legacy-only records and a note', async () => {
    const { deps, call } = setup();
    deps.official.listClients = async () => {
      throw new Error('official API timed out');
    };
    const list = (await call('unifi_list_clients')) as { total: number; note: string };
    expect(list.total).toBe(31);
    expect(list.note).toMatch(/official client list didn't answer .*guest actions are unavailable/);
    const found = (await call('unifi_get_client', { client: '02:00:00:00:00:05' })) as Row;
    expect(found.name).toBe('client-1');
    expect(found).not.toHaveProperty('officialId');
    expect(found.note).toMatch(/guest actions are unavailable/);
  });

  it('reads stat/sta once per call', async () => {
    const { deps, call } = setup();
    await call('unifi_list_clients');
    expect(deps.console.calls.filter((c) => c.endsWith('/stat/sta'))).toHaveLength(1);
  });

  it('keeps offline wired clients under the wired filter', async () => {
    const { call } = setup();
    const wired = (await call('unifi_list_clients', { wired: true, includeOffline: true })) as {
      clients: Row[];
    };
    expect(wired.clients.some((c) => c.connected === false)).toBe(true);
    expect(wired.clients.every((c) => c.wired === true)).toBe(true);
  });
});

describe('unifi_wan_status', () => {
  it('shows availability and latency per WAN from the health data', async () => {
    const { call } = setup();
    const wan = (await call('unifi_wan_status')) as { perWan: unknown };
    expect(wan.perWan).toEqual([{ name: 'WAN', availabilityPct: 100, latencyMs: 7 }]);
  });

  it('combines the WANs, gateway health and Site Manager ISP metrics', async () => {
    const { call } = setup();
    const wan = (await call('unifi_wan_status')) as Wan;
    expect(wan.wans.map((w) => w.name)).toEqual(['Internet 1', 'Internet 2']);
    expect(wan.gateway).toMatchObject({ status: 'ok', wanIp: '192.168.1.162', isp: 'Nos Comunicacoes' });
    expect(wan.internet).toMatchObject({ status: 'ok', latencyMs: 7, drops: 2 });
    expect((wan.ispMetrics as { series: unknown[] }).series[0]).toMatchObject({ periods: 714, uptimePct: expect.any(Number) });
    expect((wan.ispMetrics as { interval: string }).interval).toBe('5m');
  });

  it('says ISP metrics are unavailable without a Site Manager key', async () => {
    const { call } = setup({ sitemanager: false });
    const wan = (await call('unifi_wan_status')) as Wan;
    expect(wan.ispMetrics).toEqual({ available: false, reason: expect.stringMatching(/SITE_MANAGER/) });
  });

  it('reports a Site Manager failure without losing the local status', async () => {
    const { deps, call } = setup();
    deps.sitemanager!.ispMetrics = async () => {
      throw new Error('Site Manager is down');
    };
    const wan = (await call('unifi_wan_status')) as Wan;
    expect(wan.gateway.status).toBe('ok');
    expect(wan.ispMetrics).toEqual({ available: false, reason: 'Site Manager is down' });
  });
});

describe('unifi_vpn_status', () => {
  it('lists servers, tunnels and the vpn subsystem health', async () => {
    const { call } = setup();
    expect(await call('unifi_vpn_status')).toEqual({
      site: 'Default',
      health: 'unknown',
      servers: [],
      siteToSiteTunnels: [],
    });
  });
});

describe('unifi_events', () => {
  it('returns only the asked category and severity', async () => {
    const { call } = setup();
    const result = (await call('unifi_events', {
      category: 'SECURITY',
      minSeverity: 'VERY_HIGH',
      since: '7d',
      limit: 1000,
    })) as { events: Array<{ category: string; severity: string }> };
    expect(result.events.length).toBeGreaterThan(0);
    expect(result.events.every((e) => e.category === 'SECURITY' && e.severity === 'VERY_HIGH')).toBe(true);
  });

  it('renders the message from its template and parameters', async () => {
    const { call } = setup();
    const result = (await call('unifi_events', { text: 'data-archive', limit: 5 })) as {
      events: Array<{ message: string }>;
    };
    expect(result.events[0]!.message).toMatch(
      /^A network intrusion attempt from 203\.0\.113\.\d+ to data-archive( 00:1a)? has been detected\.$/,
    );
  });

  it('defaults to 24 h, newest first, 100 rows, and says how many were cut', async () => {
    const { call } = setup();
    const result = (await call('unifi_events')) as {
      events: Array<{ time: string }>;
      truncated: { shown: number; total: number };
      range: { from: string; to: string };
    };
    expect(result.events).toHaveLength(100);
    expect(result.truncated).toEqual({ shown: 100, total: 659 });
    const times = result.events.map((e) => e.time);
    expect([...times].sort().reverse()).toEqual(times);
    expect(Date.parse(result.range.from)).toBe(FIXTURE_NOW - 86_400_000);
  });

  it('filters by client and device through the log parameters', async () => {
    const { call } = setup();
    const byClient = (await call('unifi_events', { client: '02:00:00:00:00:1a', since: '7d', limit: 5 })) as {
      events: Array<{ message: string }>;
    };
    expect(byClient.events.length).toBeGreaterThan(0);
    expect(byClient.events.every((e) => /data-archive/.test(e.message))).toBe(true);
    const byDevice = (await call('unifi_events', { device: 'no-such-device' })) as { events: unknown[] };
    expect(byDevice.events).toEqual([]);
  });

  it('reports truncatedAt when the range is wider than the 20,000 event ceiling', async () => {
    const { deps, call } = setup({ log: syntheticLog(21_000) });
    const result = (await call('unifi_events', { since: '7d', limit: 10 })) as {
      events: unknown[];
      scan: { truncatedAt: string; note: string };
    };
    expect(result.scan.truncatedAt).toBe(new Date(FIXTURE_NOW - 19_999 * 1000).toISOString());
    expect(result.scan.note).toMatch(/stopped at 20000 events, range only covered back to 20/);
    expect(result.events).toHaveLength(10);
    expect(deps.console.calls.filter((c) => c.startsWith('POST'))).toHaveLength(20);
  });

  it('has no scan warning when the whole range was read', async () => {
    const { call } = setup();
    expect(await call('unifi_events', { since: '7d' })).not.toHaveProperty('scan');
  });

  it('rejects an unknown severity and a limit above 1000', async () => {
    const { call } = setup();
    await expect(call('unifi_events', { minSeverity: 'EXTREME' })).rejects.toThrow();
    await expect(call('unifi_events', { limit: 1001 })).rejects.toThrow();
  });
});

describe('unifi_list_hosts', () => {
  it('lists the consoles on the account', async () => {
    const { call } = setup();
    const hosts = (await call('unifi_list_hosts')) as { hosts: Row[] };
    expect(hosts.hosts).toHaveLength(1);
    expect(hosts.hosts[0]).toMatchObject({ name: 'Gateway CGU', state: 'connected', type: 'console' });
  });
});
