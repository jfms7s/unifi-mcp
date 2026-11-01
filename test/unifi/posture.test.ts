import { beforeAll, describe, expect, it } from 'vitest';
import type { FirewallPolicy, FirewallZone } from '../../src/unifi/official.js';
import {
  auditPosture,
  loadPostureInput,
  skippedRules,
  type Finding,
  type PostureInput,
} from '../../src/unifi/posture.js';
import { createReadTools } from '../../src/unifi/read-tools.js';
import { FIXTURE_NOW, caller, liveLog, readDeps } from './fixtures.js';

let live: PostureInput;

beforeAll(async () => {
  const deps = readDeps();
  const site = await deps.sites.resolve();
  live = await loadPostureInput(deps, site, { newClientDays: 7, threatDays: 7 });
});

const byRule = (findings: Finding[], rule: string) => findings.filter((f) => f.rule === rule);
const audit = (patch: Partial<PostureInput> = {}) => auditPosture({ ...live, ...patch });

describe('port-forward-open', () => {
  it('reports each enabled forward open to any source, with the inbound threats against its target', () => {
    const found = byRule(audit(), 'port-forward-open');
    expect(found.map((f) => f.object)).toEqual(['Synology', 'PLEX', 'reverse']);
    const synology = found[0]!;
    expect(synology.severity).toBe('HIGH');
    expect(synology.why).toContain('61119');
    expect(synology.why).toContain('tcp_udp');
    expect(synology.why).toContain('any source');
    expect(synology.why).toContain('192.168.10.3');
    // 897 inbound SECURITY events name data-archive (02:00:00:00:00:1a, 192.168.10.3) in the week.
    expect(synology.why).toContain('897 inbound threat events');
  });

  it('matches the target by IP: the other data-archive (192.168.0.194) does not lend its name or threats', () => {
    const [synology] = byRule(audit(), 'port-forward-open');
    expect(synology!.why).toContain('data-archive (192.168.10.3)');
    expect(synology!.why).not.toContain('192.168.0.194');
  });

  it('leaves out forwards that are disabled or limited to a source', () => {
    const [first] = live.portForwards;
    const found = byRule(
      audit({
        portForwards: [
          { ...first!, name: 'off', enabled: false },
          { ...first!, name: 'limited', src: '198.51.100.7' },
        ],
      }),
      'port-forward-open',
    );
    expect(found).toEqual([]);
  });

  it('says when the threat count is a floor because the scan stopped at the ceiling', () => {
    const [synology] = byRule(
      audit({ threats: { ...live.threats, truncatedAt: FIXTURE_NOW - 3_600_000 } }),
      'port-forward-open',
    );
    expect(synology!.why).toContain('at least 897');
  });
});

describe('wifi-weak', () => {
  const [ssid] = [() => live.wlans[0]!];

  it('flags WPA2-only SSIDs on the live console, whose U7 Lite supports WPA3', () => {
    const found = byRule(audit(), 'wifi-weak');
    expect(found.map((f) => [f.object, f.severity])).toEqual([
      ['ssid-1', 'MEDIUM'],
      ['ssid-2', 'MEDIUM'],
      ['ssid-3', 'MEDIUM'],
    ]);
    expect(found[0]!.why).toContain('WPA2 only');
    expect(found[0]!.why).toContain('device-3');
  });

  it('flags an open SSID as HIGH', () => {
    const found = byRule(
      audit({ wlans: [{ ...ssid(), name: 'cafe', security: 'open' }] }),
      'wifi-weak',
    );
    expect(found).toEqual([
      expect.objectContaining({
        object: 'cafe',
        severity: 'HIGH',
        why: expect.stringContaining('no encryption'),
      }),
    ]);
  });

  it('does not flag WPA2-only when no AP supports WPA3', () => {
    const devices = live.devices.map((d) =>
      d.model === 'U7 Lite' ? { ...d, model: 'UAP-AC-LR-Gen1' } : d,
    );
    expect(byRule(audit({ devices }), 'wifi-weak')).toEqual([]);
  });

  it('does not flag WPA2/WPA3 transition mode', () => {
    const wlans = live.wlans.map((w) => ({ ...w, wpa3_support: true, wpa3_transition: true }));
    expect(byRule(audit({ wlans }), 'wifi-weak')).toEqual([]);
  });

  it('flags a guest SSID whose clients are not isolated', () => {
    const wlans = [
      { ...ssid(), name: 'visitors', wpa3_support: true, is_guest: true, l2_isolation: false },
    ];
    expect(byRule(audit({ wlans }), 'wifi-weak')).toEqual([
      expect.objectContaining({
        object: 'visitors',
        severity: 'MEDIUM',
        why: expect.stringContaining('guest'),
      }),
    ]);
  });

  it('flags WEP and WPA1 as HIGH, WPA/WPA2 mixed (auto) as MEDIUM', () => {
    const wlans = [
      { ...ssid(), name: 'old', security: 'wep' },
      { ...ssid(), name: 'tkip', wpa_mode: 'wpa1' },
      { ...ssid(), name: 'mixed', wpa_mode: 'auto' },
    ];
    expect(byRule(audit({ wlans }), 'wifi-weak').map((f) => [f.object, f.severity])).toEqual([
      ['old', 'HIGH'],
      ['tkip', 'HIGH'],
      ['mixed', 'MEDIUM'],
    ]);
  });

  it('skips disabled SSIDs', () => {
    const wlans = [{ ...ssid(), enabled: false, security: 'open' }];
    expect(byRule(audit({ wlans }), 'wifi-weak')).toEqual([]);
  });
});

describe('zone and policy rules', () => {
  const zones: FirewallZone[] = [
    { id: 'z-int', name: 'Internal', networkIds: ['50edfc66-8b84-4f92-8753-9d69a080a695'] },
    { id: 'z-ext', name: 'External', networkIds: [] },
    { id: 'z-iot', name: 'IoT', networkIds: ['f1b4fdb6-c787-4421-92bb-56d55e0ea95a'] },
    { id: 'z-gw', name: 'Gateway', networkIds: [] },
  ];
  const policy = (
    p: Partial<FirewallPolicy> & { from: string; to: string; filtered?: boolean },
  ): FirewallPolicy => ({
    id: `p-${p.name ?? 'x'}`,
    name: p.name ?? 'x',
    enabled: p.enabled ?? true,
    action: p.action ?? { type: 'ALLOW' },
    source: { zoneId: p.from, ...(p.filtered ? { trafficFilter: { type: 'PORT' } } : {}) },
    destination: { zoneId: p.to },
    metadata: { origin: 'USER_DEFINED' },
  });
  const run = (policies: FirewallPolicy[]) => audit({ firewall: { zones, policies } });

  it('zone-allow-to-trusted: IoT allowed into Internal is MEDIUM, External into Internal is HIGH', () => {
    const findings = run([
      policy({ name: 'iot-in', from: 'z-iot', to: 'z-int', filtered: true }),
      policy({ name: 'wan-in', from: 'z-ext', to: 'z-int', filtered: true }),
      policy({ name: 'out', from: 'z-int', to: 'z-iot', filtered: true }),
      policy({ name: 'blocked', from: 'z-iot', to: 'z-int', action: { type: 'BLOCK' } }),
      policy({ name: 'off', from: 'z-ext', to: 'z-gw', enabled: false }),
    ]);
    expect(byRule(findings, 'zone-allow-to-trusted').map((f) => [f.object, f.severity])).toEqual([
      ['wan-in', 'HIGH'],
      ['iot-in', 'MEDIUM'],
    ]);
    expect(byRule(findings, 'zone-allow-to-trusted')[1]!.why).toContain('IoT → Internal');
  });

  it('policy-any-any: an unfiltered ALLOW is flagged, a filtered one is not', () => {
    const findings = run([
      policy({ name: 'everything', from: 'z-int', to: 'z-iot' }),
      policy({ name: 'web-only', from: 'z-int', to: 'z-iot', filtered: true }),
    ]);
    expect(byRule(findings, 'policy-any-any').map((f) => f.object)).toEqual(['everything']);
  });

  it('ignores system-defined policies and return-traffic-only ones', () => {
    const findings = run([
      {
        ...policy({ name: 'sys', from: 'z-ext', to: 'z-int' }),
        metadata: { origin: 'SYSTEM_DEFINED' },
      },
      {
        ...policy({ name: 'return', from: 'z-ext', to: 'z-int' }),
        connectionStateFilter: ['ESTABLISHED', 'RELATED'],
      },
    ]);
    expect(
      findings.filter((f) => f.rule.startsWith('zone') || f.rule.startsWith('policy')),
    ).toEqual([]);
  });

  it('both rules are skipped with a note while Zone-Based Firewall is off (the live console)', () => {
    expect(byRule(audit(), 'zone-allow-to-trusted')).toEqual([]);
    expect(byRule(audit(), 'policy-any-any')).toEqual([]);
    const skipped = skippedRules(live);
    expect(skipped.map((s) => s.rule)).toEqual(['zone-allow-to-trusted', 'policy-any-any']);
    expect(skipped[0]!.note).toContain('Zone-Based Firewall is not enabled');
  });

  it('nothing is skipped when the firewall was read', () => {
    expect(skippedRules({ ...live, firewall: { zones, policies: [] } })).toEqual([]);
  });
});

describe('ips-off', () => {
  const withMode = (mode: string) =>
    live.settings.map((s) => (s.key === 'ips' ? { ...s, ips_mode: mode } : s));

  it('the live console is in detect-only mode (ips_mode "ids")', () => {
    expect(byRule(audit(), 'ips-off')).toEqual([
      expect.objectContaining({ severity: 'MEDIUM', why: expect.stringContaining('detect') }),
    ]);
  });

  it('off is HIGH', () => {
    expect(byRule(audit({ settings: withMode('disabled') }), 'ips-off')).toEqual([
      expect.objectContaining({ severity: 'HIGH', why: expect.stringContaining('off') }),
    ]);
  });

  it('prevention mode is not a finding', () => {
    expect(byRule(audit({ settings: withMode('ips') }), 'ips-off')).toEqual([]);
  });

  it('an ips section without ips_mode is unknown, not off', () => {
    const settings = live.settings.map((s) => (s.key === 'ips' ? { key: 'ips' } : s));
    expect(byRule(audit({ settings }), 'ips-off')).toEqual([
      expect.objectContaining({ severity: 'LOW', why: expect.stringContaining('unknown') }),
    ]);
  });

  it('a console without the ips section is noted, not passed', () => {
    const input = { ...live, settings: live.settings.filter((s) => s.key !== 'ips') };
    expect(byRule(auditPosture(input), 'ips-off')).toEqual([]);
    expect(skippedRules(input).map((s) => s.rule)).toContain('ips-off');
  });
});

describe('new-clients and firmware-updates', () => {
  it('lists the clients first seen in the last 7 days', () => {
    const found = byRule(audit(), 'new-clients');
    expect(found.map((f) => f.object).sort()).toEqual(
      [
        'client-10 (192.168.0.11)',
        'client-13 (192.168.10.252)',
        'client-15 (192.168.0.202)',
        'client-16 (192.168.0.201)',
        'client-17 (192.168.0.200)',
        'client-18 (192.168.0.203)',
        'client-19 (192.168.0.2)',
        'client-20 (192.168.0.3)',
        'client-22 (192.168.0.231)',
        'data-archive (192.168.0.194)',
      ].sort(),
    );
    expect(found.every((f) => f.severity === 'LOW')).toBe(true);
  });

  it('honours days', () => {
    expect(byRule(audit({ newClientDays: 1 }), 'new-clients').map((f) => f.object)).toEqual([
      'client-22 (192.168.0.231)',
    ]);
  });

  it('lists upgradable devices (none on the live console)', () => {
    expect(byRule(audit(), 'firmware-updates')).toEqual([]);
    const devices = live.devices.map((d) =>
      d.name === 'device-4' ? { ...d, firmwareUpdatable: true } : d,
    );
    expect(byRule(audit({ devices }), 'firmware-updates')).toEqual([
      expect.objectContaining({ object: 'device-4', why: expect.stringContaining('2.1.8') }),
    ]);
  });
});

describe('ordering', () => {
  it('findings come HIGH first, then MEDIUM, then LOW', () => {
    const ranks = audit().map((f) => ['HIGH', 'MEDIUM', 'LOW'].indexOf(f.severity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe('security tools', () => {
  const setup = () => caller(createReadTools(readDeps()));

  it('unifi_posture_audit returns findings and the ZBF note', async () => {
    const out = (await setup()('unifi_posture_audit')) as {
      findings: Finding[];
      skipped: Array<{ rule: string; note: string }>;
      counts: Record<string, number>;
    };
    expect(out.findings.filter((f) => f.rule === 'port-forward-open')).toHaveLength(3);
    expect(out.skipped.map((s) => s.rule)).toEqual(['zone-allow-to-trusted', 'policy-any-any']);
    expect(out.counts).toEqual({ HIGH: 3, MEDIUM: 4, LOW: 10 });
  });

  it('unifi_list_firewall: the ZBF message and the legacy rules, read-only and readable', async () => {
    const out = (await setup()('unifi_list_firewall')) as {
      zoneBasedFirewall: string;
      legacy: { label: string; rules: string[] };
    };
    expect(out.zoneBasedFirewall).toContain('Zone-Based Firewall is not enabled');
    expect(out.legacy.label).toBe('legacy rules (read-only until Zone-Based Firewall is on)');
    expect(out.legacy.rules).toHaveLength(8);
    expect(out.legacy.rules).toContain(
      'WAN_IN #20000: DROP all 203.0.113.1 → 192.168.10.3 "IPS Block Traffic from 203.0.113.1 to 192.168.10.3"',
    );
  });

  it('unifi_list_port_forwards: one line per forward with its target client', async () => {
    const out = (await setup()('unifi_list_port_forwards')) as {
      forwards: Array<{ rule: string; target?: string }>;
    };
    expect(out.forwards[0]).toEqual({
      id: '69382fa41d4c99459c112d5a',
      rule: 'Synology: WAN 61119 → 192.168.10.3:6690 tcp_udp from any',
      enabled: true,
      target: 'data-archive',
    });
  });

  it('unifi_list_wifi and unifi_list_networks are compact rows', async () => {
    const call = setup();
    const wifi = (await call('unifi_list_wifi')) as { wifi: Array<Record<string, unknown>> };
    expect(wifi.wifi[1]).toEqual(
      expect.objectContaining({ name: 'ssid-2', security: 'WPA2', network: 'IoT', enabled: true }),
    );
    const nets = (await call('unifi_list_networks')) as {
      networks: Array<Record<string, unknown>>;
    };
    expect(nets.networks.find((n) => n.name === 'pi-cluster')).toEqual(
      expect.objectContaining({
        vlan: 3,
        subnet: '192.168.0.1/24',
        id: '80ec407d-e455-4a87-8b26-846881ebf07f',
        legacyId: '6ae51197aa840627805aa50a',
      }),
    );
    expect(nets.networks.find((n) => n.name === 'Internet 1')).toEqual(
      expect.objectContaining({ purpose: 'wan', wanIp: '192.168.1.162' }),
    );
  });

  it('unifi_audit_log is newest first even when the log arrives oldest first', async () => {
    const call = caller(createReadTools(readDeps({ log: [...liveLog()].reverse() })));
    const out = (await call('unifi_audit_log')) as { entries: Array<{ time: string }> };
    const times = out.entries.map((e) => e.time);
    expect(times.length).toBeGreaterThan(1);
    expect(times).toEqual([...times].sort().reverse());
  });

  it('unifi_audit_log lists AUDIT entries and filters by actor', async () => {
    const call = setup();
    const all = (await call('unifi_audit_log')) as {
      total: number;
      entries: Array<{ actor?: string; message: string }>;
    };
    expect(all.total).toBe(113);
    expect(all.entries[0]).toEqual(
      expect.objectContaining({ actor: 'user-1', action: 'Network Accessed' }),
    );
    const one = (await call('unifi_audit_log', { actor: 'USER-2' })) as {
      entries: Array<{ actor?: string }>;
    };
    expect(one.entries.length).toBeGreaterThan(0);
    expect(one.entries.every((e) => e.actor === 'user-2')).toBe(true);
    const none = (await call('unifi_audit_log', { actor: 'unifi-mcp' })) as { total: number };
    expect(none.total).toBe(0);
  });
});
