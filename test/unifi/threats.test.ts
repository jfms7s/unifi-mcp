import { beforeAll, describe, expect, it } from 'vitest';
import type { KnownClient, PortForward } from '../../src/unifi/legacy.js';
import type { SyslogEntry } from '../../src/unifi/syslog.js';
import { summariseThreats, type ThreatGroup, type ThreatSummary } from '../../src/unifi/threats.js';
import { createReadTools } from '../../src/unifi/read-tools.js';
import { FIXTURE_NOW, caller, readDeps, syntheticLog } from './fixtures.js';

const WEEK_MS = 7 * 86_400_000;
const RANGE = { from: FIXTURE_NOW - WEEK_MS, to: FIXTURE_NOW };

let entries: SyslogEntry[];
let forwards: PortForward[];
let clients: KnownClient[];

beforeAll(async () => {
  const deps = readDeps();
  entries = (await deps.syslog.scan('default', { ...RANGE, ceiling: 20_000 })).entries;
  forwards = await deps.legacy.portForwards('default');
  clients = await deps.legacy.knownClients('default');
});

const summary = (opts: Partial<Parameters<typeof summariseThreats>[3]> = {}, log = entries) =>
  summariseThreats(log, forwards, clients, { maxGroups: 15, range: RANGE, ...opts });

const find = (s: ThreatSummary, direction: ThreatGroup['direction'], lanSide: string) =>
  s.groups.filter((g) => g.direction === direction && g.lanSide === lanSide);

/** A security entry with just the parameters a test cares about. */
function entry(
  id: string,
  key: string,
  parameters: SyslogEntry['parameters'],
  severity: SyslogEntry['severity'] = 'HIGH',
): SyslogEntry {
  return {
    id,
    timestamp: FIXTURE_NOW - 1000,
    category: 'SECURITY',
    severity,
    key,
    title: 'Threat Detected',
    messageTemplate: '',
    parameters,
  };
}

describe('summariseThreats on the 7-day capture', () => {
  it('folds every outbound pi-cluster event into one group with its distinct remotes', () => {
    const [group, ...more] = find(summary(), 'outbound', 'pi-cluster');
    expect(more).toEqual([]);
    expect(group?.count).toBe(2340);
    expect(group?.distinctRemotes).toBeGreaterThan(1);
    expect(group?.maxSeverity).toBe('VERY_HIGH');
    expect(group?.topRemotes).toHaveLength(5);
  });

  it('shows the inbound data-archive group with the forwards that point at its IP', () => {
    const [group, ...more] = find(summary(), 'inbound', 'data-archive 00:1a');
    expect(more).toEqual([]);
    expect(group?.portForwards?.map((f) => f.name)).toEqual(['Synology', 'PLEX', 'reverse']);
    expect(group?.portForwards?.[0]).toEqual({
      name: 'Synology',
      ports: '61119 -> 6690',
      proto: 'tcp_udp',
      source: 'any',
    });
  });

  it('gives forwards to no other group, outbound data-archive included', () => {
    const others = summary().groups.filter(
      (g) => !(g.direction === 'inbound' && g.lanSide === 'data-archive 00:1a'),
    );
    expect(others.filter((g) => g.portForwards)).toEqual([]);
  });

  it('ranks by severity, then count', () => {
    const groups = summary().groups;
    expect(groups.map((g) => `${g.maxSeverity} ${g.direction} ${g.lanSide}`).slice(0, 3)).toEqual([
      'VERY_HIGH outbound pi-cluster',
      'VERY_HIGH inbound data-archive 00:1a',
      'HIGH outbound MAC Hub',
    ]);
  });

  it('accounts for every security event, and nothing else', () => {
    const s = summary();
    expect(s.totalEvents).toBe(4516);
    expect(s.groups.reduce((n, g) => n + g.count, 0)).toBe(4516);
    expect(s.tail).toBeUndefined();
  });

  it('summarises the groups past maxGroups as a tail, never dropping them', () => {
    const all = summary().groups.length;
    const s = summary({ maxGroups: 2 });
    expect(s.groups).toHaveLength(2);
    expect(s.tail!.groups + 2).toBe(all);
    expect(s.tail!.events + s.groups[0]!.count + s.groups[1]!.count).toBe(s.totalEvents);
  });

  it('lists a remote that touched two LAN clients with both lanSides', () => {
    const remote = summary().topRemotesOverall.find((r) => r.ip === '203.0.113.7');
    expect(remote?.lanSides.sort()).toEqual(['MAC Hub', 'client-1 00:05']);
    expect(summary().topRemotesOverall.length).toBeLessThanOrEqual(10);
  });

  it('marks a complete range as complete', () => {
    expect(summary().range).toEqual({
      from: new Date(RANGE.from).toISOString(),
      to: new Date(RANGE.to).toISOString(),
      complete: true,
    });
  });

  it('says how far back it got when the scan was cut', () => {
    const cut = FIXTURE_NOW - 86_400_000;
    const range = summary({ truncatedAt: cut }).range;
    expect(range.complete).toBe(false);
    expect(range.truncatedAt).toBe(new Date(cut).toISOString());
    expect(range.note).toMatch(/stopped at 20000 events, range only covered back to/);
  });
});

describe('summariseThreats on synthetic entries', () => {
  const both = [
    entry('a', 'THREAT_DETECTED_KNOWN_DESTINATION_CLIENT', {
      DST_CLIENT: { id: '02:00:00:00:00:aa', name: 'pi-cluster' },
      SRC_IP: { id: '198.51.100.1', name: '198.51.100.1' },
    }),
    entry('b', 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', {
      SRC_CLIENT: { id: '02:00:00:00:00:aa', name: 'pi-cluster' },
      DST_IP: { id: '198.51.100.2', name: '198.51.100.2' },
    }),
  ];

  it('never merges inbound and outbound for the same client', () => {
    const s = summary({}, both);
    expect(s.groups.map((g) => [g.direction, g.lanSide, g.count])).toEqual([
      ['inbound', 'pi-cluster', 1],
      ['outbound', 'pi-cluster', 1],
    ]);
    expect(s.groups[0]!.topRemotes).toEqual([{ ip: '198.51.100.1', count: 1 }]);
    expect(s.groups[1]!.topRemotes).toEqual([{ ip: '198.51.100.2', count: 1 }]);
  });

  it('gives an unknown security key its own other group', () => {
    const s = summary({}, [
      ...both,
      entry('c', 'THREAT_SOMETHING_NEW', { SRC_IP: { id: '192.0.2.9', name: '192.0.2.9' } }, 'LOW'),
    ]);
    const [group, ...more] = find(s, 'other', 'THREAT_SOMETHING_NEW');
    expect(more).toEqual([]);
    expect(group).toMatchObject({ count: 1, maxSeverity: 'LOW', keys: ['THREAT_SOMETHING_NEW'] });
  });

  it('groups firewall blocks by trigger, falling back to "firewall"', () => {
    const s = summary({}, [
      entry('d', 'TRAFFIC_BLOCKED', { SRC_IP: { id: '192.0.2.1', name: '192.0.2.1' } }, 'MEDIUM'),
    ]);
    expect(s.groups.map((g) => [g.direction, g.lanSide])).toEqual([['blocked', 'firewall']]);
  });

  it('matches forwards by DST_IP for an inbound event without DST_CLIENT', () => {
    const lanIp = forwards[0]!.fwd;
    const s = summary({}, [
      entry('e', 'THREAT_DETECTED_KNOWN_DESTINATION_CLIENT', {
        DST_IP: { id: lanIp, name: lanIp },
        SRC_IP: { id: '198.51.100.3', name: '198.51.100.3' },
      }),
    ]);
    expect(s.groups).toHaveLength(1);
    expect(s.groups[0]).toMatchObject({ direction: 'inbound', lanSide: lanIp });
    expect(s.groups[0]!.portForwards?.map((f) => f.name)).toEqual(['Synology', 'PLEX', 'reverse']);
  });

  it('groups firewall blocks by trigger, then by the LAN address, naming its client', () => {
    const lanIp = forwards[0]!.fwd;
    const known = clients.find((c) => c.ip === lanIp)!.name;
    const block = (id: string, trigger: string, dst: string) =>
      entry(
        id,
        'TRAFFIC_BLOCKED',
        {
          TRIGGER: { id: trigger, name: trigger },
          DST_IP: { id: dst, name: dst },
          SRC_IP: { id: '192.0.2.1', name: '192.0.2.1' },
        },
        'MEDIUM',
      );
    const s = summary({}, [
      block('f1', 'Block A', lanIp),
      block('f2', 'Block A', lanIp),
      block('f3', 'Block A', '192.168.1.250'),
      block('f4', 'Block B', lanIp),
    ]);
    expect(s.groups.map((g) => [g.direction, g.lanSide, g.count])).toEqual([
      ['blocked', `Block A -> ${known} (${lanIp})`, 2],
      ['blocked', 'Block A -> 192.168.1.250', 1],
      ['blocked', `Block B -> ${known} (${lanIp})`, 1],
    ]);
  });

  it('a block picks its LAN side by address: a private DST is inbound, else a private SRC is outbound', () => {
    const lanIp = forwards[0]!.fwd;
    const known = clients.find((c) => c.ip === lanIp)!.name;
    const ip = (a: string) => ({ id: a, name: a });
    const block = (id: string, src: string, dst: string) =>
      entry(id, 'TRAFFIC_BLOCKED', { TRIGGER: ip('Block C'), SRC_IP: ip(src), DST_IP: ip(dst) }, 'MEDIUM');
    const log = [
      block('b1', '198.51.100.7', lanIp),
      block('b2', lanIp, '203.0.113.1'),
      block('b3', lanIp, '203.0.113.2'),
      block('b4', '10.0.0.5', '172.16.0.9'),
      block('b5', '172.31.0.4', '198.51.100.8'),
      block('b6', '198.51.100.9', '203.0.113.3'),
    ];
    const s = summary({}, log);
    expect(s.groups.map((g) => [g.lanSide, g.count, g.topRemotes.map((r) => r.ip)])).toEqual([
      [`Block C, outbound from ${known} (${lanIp})`, 2, ['203.0.113.1', '203.0.113.2']],
      ['Block C -> 172.16.0.9', 1, ['10.0.0.5']],
      ['Block C -> 203.0.113.3', 1, ['198.51.100.9']],
      [`Block C -> ${known} (${lanIp})`, 1, ['198.51.100.7']],
      ['Block C, outbound from 172.31.0.4', 1, ['198.51.100.8']],
    ]);
    expect(s.totalEvents).toBe(log.length);
    expect(s.groups.reduce((n, g) => n + g.count, 0)).toBe(log.length);
    const cut = summary({ maxGroups: 2 }, log);
    expect(cut.groups.reduce((n, g) => n + g.count, 0) + (cut.tail?.events ?? 0)).toBe(log.length);
  });

  it('CGNAT, link-local and IPv6 ULA / link-local addresses count as the LAN side', () => {
    const ip = (a: string) => ({ id: a, name: a });
    const out = (id: string, src: string) =>
      entry(id, 'TRAFFIC_BLOCKED', { TRIGGER: ip('Block D'), SRC_IP: ip(src), DST_IP: ip('203.0.113.9') }, 'MEDIUM');
    const s = summary({}, [
      out('c1', '100.64.0.1'),
      out('c2', '100.127.255.254'),
      out('c3', '169.254.1.1'),
      out('c4', 'fd12:3456::1'),
      out('c5', 'fe80::1'),
      out('c6', '100.128.0.1'),
      out('c7', 'fc00::1'),
    ]);
    const outbound = s.groups.filter((g) => g.lanSide.includes('outbound from')).map((g) => g.lanSide);
    expect(outbound.sort()).toEqual(
      ['100.127.255.254', '100.64.0.1', '169.254.1.1', 'fd12:3456::1', 'fe80::1'].map(
        (a) => `Block D, outbound from ${a}`,
      ).sort(),
    );
    expect(s.groups.filter((g) => g.lanSide === 'Block D -> 203.0.113.9')).toHaveLength(1);
    expect(s.groups.find((g) => g.lanSide === 'Block D -> 203.0.113.9')!.count).toBe(2);
  });

  it('on the capture, every event is in a group or the tail', () => {
    const s = summary({ maxGroups: 3 });
    expect(s.totalEvents).toBe(4516);
    expect(s.groups.reduce((n, g) => n + g.count, 0) + (s.tail?.events ?? 0)).toBe(4516);
  });

  it('orders ties by lanSide, then direction, and equal remotes by IP', () => {
    const remote = (ip: string) => ({ id: ip, name: ip });
    const s = summary({}, [
      entry('t1', 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', {
        SRC_CLIENT: { id: '02:00:00:00:00:bb', name: 'zeta' },
        DST_IP: remote('198.51.100.9'),
      }),
      entry('t2', 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', {
        SRC_CLIENT: { id: '02:00:00:00:00:aa', name: 'alpha' },
        DST_IP: remote('198.51.100.9'),
      }),
      entry('t3', 'THREAT_DETECTED_KNOWN_DESTINATION_CLIENT', {
        DST_CLIENT: { id: '02:00:00:00:00:aa', name: 'alpha' },
        SRC_IP: remote('198.51.100.8'),
      }),
      entry('t4', 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', {
        SRC_CLIENT: { id: '02:00:00:00:00:cc', name: 'mid' },
        DST_IP: remote('198.51.100.7'),
      }),
      entry('t5', 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', {
        SRC_CLIENT: { id: '02:00:00:00:00:cc', name: 'mid' },
        DST_IP: remote('198.51.100.5'),
      }),
    ]);
    expect(s.groups.map((g) => `${g.direction} ${g.lanSide}`)).toEqual([
      'outbound mid',
      'inbound alpha',
      'outbound alpha',
      'outbound zeta',
    ]);
    expect(s.groups[0]!.topRemotes.map((r) => r.ip)).toEqual(['198.51.100.5', '198.51.100.7']);
    expect(s.topRemotesOverall.map((r) => r.ip)).toEqual([
      '198.51.100.9',
      '198.51.100.5',
      '198.51.100.7',
      '198.51.100.8',
    ]);
  });

  it('ignores entries outside the SECURITY category', () => {
    const s = summary({}, [{ ...both[0]!, category: 'CLIENT_DEVICES' }]);
    expect(s.totalEvents).toBe(0);
    expect(s.groups).toEqual([]);
  });
});

describe('unifi_threat_summary', () => {
  const call = (args: Record<string, unknown>, opts: Parameters<typeof readDeps>[0] = {}) =>
    caller(createReadTools(readDeps(opts)))('unifi_threat_summary', args) as Promise<
      ThreatSummary & { site: string }
    >;

  it('defaults to the last 7 days from the injected now', async () => {
    const result = await call({});
    expect(result.site).toBeTruthy();
    expect(result.range.from).toBe(new Date(FIXTURE_NOW - WEEK_MS).toISOString());
    expect(result.range.to).toBe(new Date(FIXTURE_NOW).toISOString());
    expect(result.range.complete).toBe(true);
    expect(result.groups[0]).toMatchObject({ direction: 'outbound', lanSide: 'pi-cluster' });
  });

  it('honours maxGroups', async () => {
    const result = await call({ maxGroups: 3 });
    expect(result.groups).toHaveLength(3);
    expect(result.tail?.groups).toBeGreaterThan(0);
  });

  it('reports a range cut short by the 20,000 event ceiling', async () => {
    const result = await call({}, { log: syntheticLog(21_000) });
    expect(result.range.complete).toBe(false);
    expect(result.range.truncatedAt).toBe(new Date(FIXTURE_NOW - 19_999 * 1000).toISOString());
  });
});
