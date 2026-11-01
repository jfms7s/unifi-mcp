import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  FIREWALL_FIXTURES,
  firewallEndpoints,
  orderingPairs,
  parseOnly,
  pickDeviceFields,
  siteIdFor,
  writeFixtures,
} from '../scripts/capture-fixtures.js';

describe('writeFixtures', () => {
  let root: string;
  let outDir: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'unifi-fixtures-'));
    outDir = join(root, 'live');
    await mkdir(outDir);
    await writeFile(join(outDir, 'old.json'), '{"old":true}\n');
  });
  afterEach(() => rm(root, { recursive: true, force: true }));

  it('leaves the previous fixtures in place and fails when any endpoint failed', async () => {
    const captured = [{ name: 'legacy-stat-sta', data: { data: [] } }];
    await expect(writeFixtures(captured, ['rest/user: timed out'], outDir)).rejects.toThrow(
      /capture incomplete[\s\S]*rest\/user: timed out/,
    );
    expect(await readdir(outDir)).toEqual(['old.json']);
    expect(await readdir(root)).toEqual(['live']);
  });

  it('replaces the folder with scrubbed fixtures when everything was captured', async () => {
    const captured = [{ name: 'legacy-stat-sta', data: { data: [{ mac: 'a4:b1:c2:d3:e4:f5' }] } }];
    await writeFixtures(captured, [], outDir);
    expect(await readdir(outDir)).toEqual(['legacy-stat-sta.json']);
    expect(JSON.parse(await readFile(join(outDir, 'legacy-stat-sta.json'), 'utf8'))).toEqual({
      data: [{ mac: '02:00:00:00:00:01' }],
    });
    expect(await readdir(root)).toEqual(['live']);
  });

  it('with only: writes just those files and leaves every other fixture alone', async () => {
    await writeFile(join(outDir, 'official-firewall-zones.json'), '{"stale":true}\n');
    const captured = [
      { name: 'official-sites', data: { data: [] }, contextOnly: true },
      { name: 'official-firewall-zones', data: { data: [{ name: 'Internal' }] } },
    ];
    await writeFixtures(captured, [], outDir, { only: true });
    expect((await readdir(outDir)).sort()).toEqual(['official-firewall-zones.json', 'old.json']);
    expect(await readFile(join(outDir, 'old.json'), 'utf8')).toBe('{"old":true}\n');
    expect(JSON.parse(await readFile(join(outDir, 'official-firewall-zones.json'), 'utf8'))).toEqual(
      { data: [{ name: 'Internal' }] },
    );
    expect(await readdir(root)).toEqual(['live']);
  });

  it('with only: a failure writes nothing', async () => {
    const captured = [{ name: 'official-firewall-zones', data: { data: [] } }];
    await expect(
      writeFixtures(captured, ['official-firewall-policies: timed out'], outDir, { only: true }),
    ).rejects.toThrow(/capture incomplete/);
    expect(await readdir(outDir)).toEqual(['old.json']);
  });

  it('context-only captures prime the scrub but are never written', async () => {
    const realSite = '11111111-2222-4333-8444-555555555555';
    const captured = [
      { name: 'official-sites', data: { data: [{ id: realSite, internalReference: 'default', name: 'Default' }] }, contextOnly: true },
      { name: 'official-firewall-zones', data: { requestPath: `/v1/sites/${realSite}/firewall/zones` } },
    ];
    await writeFixtures(captured, [], outDir, { only: true });
    expect((await readdir(outDir)).sort()).toEqual(['official-firewall-zones.json', 'old.json']);
    const zones = await readFile(join(outDir, 'official-firewall-zones.json'), 'utf8');
    expect(zones).not.toContain(realSite);
  });

  it('fakes the public IPs in IPS auto-block names and filters, keeps private ones', async () => {
    const policy = {
      name: 'IPS Block Traffic from 45.6.7.8 to 192.168.10.3',
      source: {
        trafficFilter: {
          type: 'IP_ADDRESS',
          ipAddressFilter: { type: 'IP_ADDRESSES', items: [{ type: 'IP_ADDRESS', value: '45.6.7.8' }] },
        },
      },
      destination: {
        trafficFilter: {
          type: 'IP_ADDRESS',
          ipAddressFilter: { type: 'IP_ADDRESSES', items: [{ type: 'IP_ADDRESS', value: '192.168.10.3' }] },
        },
      },
    };
    await writeFixtures([{ name: 'official-firewall-policies', data: { data: [policy] } }], [], outDir, {
      only: true,
    });
    const text = await readFile(join(outDir, 'official-firewall-policies.json'), 'utf8');
    expect(text).not.toContain('45.6.7.8');
    expect(text).toContain('192.168.10.3');
    const [row] = (JSON.parse(text) as { data: Array<typeof policy> }).data;
    const fake = /^IPS Block Traffic from (\S+) to 192\.168\.10\.3$/.exec(row!.name)?.[1];
    expect(fake).toMatch(/^203\.0\.113\.\d+$/);
    expect(row!.source.trafficFilter.ipAddressFilter.items[0]!.value).toBe(fake);
  });
});

describe('--only firewall', () => {
  it('parses the filter; anything else is an error', () => {
    expect(parseOnly([])).toBeUndefined();
    expect(parseOnly(['--only', 'firewall'])).toBe('firewall');
    expect(parseOnly(['--only=firewall'])).toBe('firewall');
    expect(parseOnly(['--only', 'devices'])).toBe('devices');
    expect(() => parseOnly(['--only', 'wifi'])).toThrow('--only takes: firewall, devices');
    expect(() => parseOnly(['--only'])).toThrow('--only takes: firewall, devices');
  });

  it('captures the official zones, policies, ACL rules, DNS policies and traffic lists', () => {
    const site = '11111111-2222-4333-8444-555555555555';
    expect(firewallEndpoints(site).map((e) => [e.name, e.path])).toEqual([
      ['official-firewall-zones', `/v1/sites/${site}/firewall/zones?limit=200`],
      ['official-firewall-policies', `/v1/sites/${site}/firewall/policies?limit=200`],
      ['official-acl-rules', `/v1/sites/${site}/acl-rules?limit=200`],
      ['official-dns-policies', `/v1/sites/${site}/dns/policies?limit=200`],
      ['official-traffic-matching-lists', `/v1/sites/${site}/traffic-matching-lists?limit=200`],
    ]);
    expect(FIREWALL_FIXTURES).toEqual([
      ...firewallEndpoints(site).map((e) => e.name),
      'official-firewall-policies-ordering',
    ]);
  });

  it('asks for the ordering of every zone pair', () => {
    expect(orderingPairs({ data: [{ id: 'a' }, { id: 'b' }] })).toEqual([
      { sourceZoneId: 'a', destinationZoneId: 'a' },
      { sourceZoneId: 'a', destinationZoneId: 'b' },
      { sourceZoneId: 'b', destinationZoneId: 'a' },
      { sourceZoneId: 'b', destinationZoneId: 'b' },
    ]);
    expect(() => orderingPairs({})).toThrow('no zones');
  });
});

describe('--only devices', () => {
  it('keeps only the stat/device fields the device summary reads', () => {
    const raw = {
      meta: { rc: 'ok' },
      data: [
        {
          mac: '02:00:00:00:00:05',
          name: 'Switch',
          type: 'usw',
          model: 'USM8P60',
          state: 1,
          serial: '020000000005',
          config_network: { ip: '192.168.1.2' },
          uplink: { uplink_mac: '02:00:00:00:00:01', uplink_device_name: 'Gw', uplink_remote_port: 3, type: 'wire', up: true, ip: '192.168.1.2' },
          last_uplink: { uplink_mac: '02:00:00:00:00:01', uplink_device_name: 'Gw', uplink_remote_port: 3, type: 'wire' },
          port_table: [
            { port_idx: 1, up: true, name: 'NAS', port_poe: true, poe_enable: true, poe_good: true, poe_power: '3.55', speed: 1000, is_uplink: false, mac_table: [] },
          ],
          radio_table_stats: [{ name: 'wifi0', radio: 'ng', channel: 11, num_sta: 9, tx_power: 20 }],
        },
      ],
    };
    expect(pickDeviceFields(raw)).toEqual({
      meta: { rc: 'ok' },
      data: [
        {
          mac: '02:00:00:00:00:05',
          name: 'Switch',
          type: 'usw',
          model: 'USM8P60',
          state: 1,
          uplink: { uplink_mac: '02:00:00:00:00:01', uplink_remote_port: 3, type: 'wire', up: true },
          last_uplink: { uplink_mac: '02:00:00:00:00:01', uplink_remote_port: 3, type: 'wire' },
          port_table: [
            { port_idx: 1, up: true, port_poe: true, poe_enable: true, poe_good: true, poe_power: '3.55', speed: 1000, is_uplink: false },
          ],
          radio_table_stats: [{ name: 'wifi0', radio: 'ng', channel: 11, num_sta: 9 }],
        },
      ],
    });
  });
});

describe('siteIdFor', () => {
  const sites = {
    data: [
      { id: '00000000-0000-4000-8000-0000000000aa', internalReference: 'other', name: 'Other' },
      { id: '00000000-0000-4000-8000-0000000000bb', internalReference: 'default', name: 'Default' },
    ],
  };

  it('reads the site id from the console instead of hardcoding it', () => {
    expect(siteIdFor(sites, 'default')).toBe('00000000-0000-4000-8000-0000000000bb');
  });

  it('a console without that site is an error', () => {
    expect(() => siteIdFor(sites, 'missing')).toThrow('the console has no site "missing"');
    expect(() => siteIdFor({}, 'default')).toThrow('the console has no site "default"');
  });
});
