import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import {
  NETS,
  SYSTEM_POLICY,
  WARNING,
  ZBF_MESSAGE,
  ZONES,
  ordering,
  policies,
  userPolicy,
  zones,
  without,
} from './firewall-fixtures.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);

type Out = Record<string, unknown>;

/** A user-defined DMZ → External block: touches nothing protected. */
const DMZ_OUT = userPolicy(
  '11111111-0000-4000-8000-000000000001',
  'dmz-out',
  ZONES.dmz,
  ZONES.external,
);
/** A user-defined Internal → External block: Internal holds pi-cluster (R19). */
const LAN_OUT = userPolicy(
  '11111111-0000-4000-8000-000000000002',
  'lan-out',
  ZONES.internal,
  ZONES.external,
  {
    enabled: false,
  },
);
const WITH_USER = { fixtures: { 'official-firewall-policies': policies(DMZ_OUT, LAN_OUT) } };
const POLICY_PATH = (id: string) => `${OFFICIAL_SITE}/firewall/policies/${id}`;
const created = { officialReply: { id: '22222222-0000-4000-8000-000000000009' } };

/** One call per firewall tool, with arguments that would otherwise get past validation. */
const EVERY_FIREWALL_CALL: Array<[string, Record<string, unknown>]> = [
  [
    'unifi_create_firewall_policy',
    { name: 'x', action: 'BLOCK', source: { zone: 'Dmz' }, destination: { zone: 'External' } },
  ],
  ['unifi_update_firewall_policy', { policy: 'dmz-out', name: 'y', confirm: true }],
  ['unifi_set_firewall_policy_enabled', { policy: 'dmz-out', enabled: false }],
  ['unifi_delete_firewall_policy', { policy: 'dmz-out', confirm: true }],
  [
    'unifi_reorder_firewall_policies',
    {
      sourceZone: 'Dmz',
      destinationZone: 'External',
      beforeSystemDefined: ['dmz-out'],
      confirm: true,
    },
  ],
  ['unifi_create_firewall_zone', { name: 'IoT zone', networks: ['IoT'] }],
  ['unifi_update_firewall_zone', { zone: 'Dmz', name: 'y', confirm: true }],
  ['unifi_delete_firewall_zone', { zone: 'Dmz', confirm: true }],
  ['unifi_block_ip', { ip: '198.51.100.7', confirm: true }],
  ['unifi_unblock_ip', { ip: '198.51.100.7', confirm: true }],
];

describe('Zone-Based Firewall off (Review Focus 5)', () => {
  it.each(EVERY_FIREWALL_CALL)('%s says to turn it on and sends nothing', async (name, args) => {
    const { call, writes } = setup({ zbfOff: true });
    await expect(call(name, args)).rejects.toThrow(ZBF_MESSAGE);
    expect(writes).toEqual([]);
  });
});

describe('unifi_create_firewall_policy', () => {
  it('is easy when neither side reaches a protected network: one POST, zones by name', async () => {
    const { call, writes } = setup(created);
    const out = (await call('unifi_create_firewall_policy', {
      name: 'no-dmz-out',
      action: 'BLOCK',
      source: { zone: 'dmz' },
      destination: { zone: 'External' },
    })) as Out;
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/firewall/policies`,
        body: {
          name: 'no-dmz-out',
          enabled: true,
          action: { type: 'BLOCK' },
          source: { zoneId: ZONES.dmz },
          destination: { zoneId: ZONES.external },
          ipProtocolScope: { ipVersion: 'IPV4_AND_IPV6' },
          loggingEnabled: false,
        },
      },
    ]);
    expect(out).toMatchObject({
      changed: 'created',
      policy: {
        id: '22222222-0000-4000-8000-000000000009',
        rule: 'Dmz → External: BLOCK all "no-dmz-out"',
      },
    });
  });

  it('ALLOW carries allowReturnTraffic (false unless asked)', async () => {
    const { call, writes } = setup(created);
    await call('unifi_create_firewall_policy', {
      name: 'dmz-web',
      action: 'ALLOW',
      source: { zone: 'Dmz' },
      destination: { zone: 'External' },
    });
    expect(writes[0]!.body).toMatchObject({ action: { type: 'ALLOW', allowReturnTraffic: false } });
  });

  it('a side that is the Internal zone alone is confirm-level (R19): preview, nothing sent', async () => {
    const { call, writes } = setup(created);
    const out = (await call('unifi_create_firewall_policy', {
      name: 'lan-out',
      action: 'BLOCK',
      source: { zone: 'Internal' },
      destination: { zone: 'External' },
    })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBe(
      `${WARNING} the policy's source includes pi-cluster, a protected network`,
    );
    expect(out.requires).toBe('confirm: true');
    expect(out.preview).toMatchObject({
      would: 'create firewall policy',
      rule: 'Internal → External: BLOCK all "lan-out"',
    });
  });

  it('with confirm it is sent once and the result repeats the warning', async () => {
    const { call, writes } = setup(created);
    const out = (await call('unifi_create_firewall_policy', {
      name: 'lan-out',
      action: 'BLOCK',
      source: { zone: 'Internal' },
      destination: { zone: 'External' },
      confirm: true,
    })) as Out;
    expect(writes).toHaveLength(1);
    expect(out.warning).toContain(WARNING);
  });

  it('an IP filter inside Default is easy; one inside 192.168.0.0/24 is confirm-level', async () => {
    const filter = (value: string) => ({
      type: 'IP_ADDRESS',
      ipAddressFilter: {
        type: 'IP_ADDRESSES',
        matchOpposite: false,
        items: [{ type: 'IP_ADDRESS', value }],
      },
    });
    const easy = setup(created);
    await easy.call('unifi_create_firewall_policy', {
      name: 'nas-out',
      action: 'BLOCK',
      source: { zone: 'Internal', trafficFilter: filter('192.168.10.3') },
      destination: { zone: 'External' },
    });
    expect(easy.writes).toHaveLength(1);

    const guardedOne = setup(created);
    const out = (await guardedOne.call('unifi_create_firewall_policy', {
      name: 'node-out',
      action: 'BLOCK',
      source: { zone: 'Internal', trafficFilter: filter('192.168.0.17') },
      destination: { zone: 'External' },
    })) as Out;
    expect(guardedOne.writes).toEqual([]);
    expect(out.warning).toContain('192.168.0.17, inside pi-cluster (192.168.0.0/24)');
  });

  it('an unknown zone is an error that names the zones', async () => {
    const { call, writes } = setup(created);
    await expect(
      call('unifi_create_firewall_policy', {
        name: 'x',
        action: 'BLOCK',
        source: { zone: 'IoT' },
        destination: { zone: 'External' },
      }),
    ).rejects.toThrow(
      'No firewall zone matches "IoT"; the zones are: Dmz, Gateway, External, Hotspot, Vpn, Internal',
    );
    expect(writes).toEqual([]);
  });
});

describe('unifi_update_firewall_policy', () => {
  it('is always confirm-level: previews only the changed fields', async () => {
    const { call, writes } = setup(WITH_USER);
    const out = (await call('unifi_update_firewall_policy', {
      policy: 'dmz-out',
      action: 'REJECT',
      loggingEnabled: true,
    })) as Out;
    expect(writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'update firewall policy',
        policy: 'dmz-out',
        changes: {
          'action.type': { before: 'BLOCK', after: 'REJECT' },
          loggingEnabled: { before: false, after: true },
        },
      },
      requires: 'confirm: true',
    });
  });

  it('with confirm PUTs the whole merged policy, minus id, metadata and index', async () => {
    const { call, writes } = setup(WITH_USER);
    await call('unifi_update_firewall_policy', {
      policy: DMZ_OUT.id,
      loggingEnabled: true,
      confirm: true,
    });
    const rest = without(DMZ_OUT, 'id', 'metadata', 'index');
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: POLICY_PATH(DMZ_OUT.id as string),
        body: { ...rest, loggingEnabled: true },
      },
    ]);
  });

  it('moving a side into the Internal zone warns about pi-cluster', async () => {
    const { call } = setup(WITH_USER);
    const out = (await call('unifi_update_firewall_policy', {
      policy: 'dmz-out',
      destination: { zone: 'Internal' },
    })) as Out;
    expect(out.warning).toContain('destination includes pi-cluster');
  });

  it('a trafficFilter of null removes the filter', async () => {
    const filtered = userPolicy(
      '11111111-0000-4000-8000-000000000003',
      'filtered',
      ZONES.dmz,
      ZONES.external,
      {
        destination: {
          zoneId: ZONES.external,
          trafficFilter: {
            type: 'PORT',
            portFilter: {
              type: 'PORTS',
              matchOpposite: false,
              items: [{ type: 'PORT_NUMBER', value: 25 }],
            },
          },
        },
      },
    );
    const { call, writes } = setup({
      fixtures: { 'official-firewall-policies': policies(filtered) },
    });
    await call('unifi_update_firewall_policy', {
      policy: 'filtered',
      destination: { trafficFilter: null },
      confirm: true,
    });
    expect((writes[0]!.body as Out).destination).toEqual({ zoneId: ZONES.external });
  });

  it('refuses a system-defined policy, even with confirm', async () => {
    const { call, writes } = setup(WITH_USER);
    await expect(
      call('unifi_update_firewall_policy', {
        policy: SYSTEM_POLICY,
        enabled: false,
        confirm: true,
      }),
    ).rejects.toThrow(
      '"Allow All Traffic" (Internal → Internal) is a system-defined policy; UniFi manages it',
    );
    expect(writes).toEqual([]);
  });

  it('refuses an IPS auto-block: the console gives it no id', async () => {
    const { call, writes } = setup(WITH_USER);
    await expect(
      call('unifi_update_firewall_policy', {
        policy: 'IPS Block Traffic from 203.0.113.1 to 192.168.10.3',
        enabled: false,
        confirm: true,
      }),
    ).rejects.toThrow(/IPS auto-block.*no id/);
    expect(writes).toEqual([]);
  });

  it('an ambiguous name returns the candidates, never a guess', async () => {
    const twin = userPolicy(
      '11111111-0000-4000-8000-000000000004',
      'dmz-out',
      ZONES.dmz,
      ZONES.vpn,
    );
    const { call, writes } = setup({
      fixtures: { 'official-firewall-policies': policies(DMZ_OUT, twin) },
    });
    const out = (await call('unifi_update_firewall_policy', {
      policy: 'dmz-out',
      enabled: false,
      confirm: true,
    })) as Out;
    expect(out).toMatchObject({ ambiguous: true });
    expect(out.candidates).toEqual([
      { id: DMZ_OUT.id, name: 'dmz-out', zones: 'Dmz → External', origin: 'USER_DEFINED' },
      { id: twin.id, name: 'dmz-out', zones: 'Dmz → Vpn', origin: 'USER_DEFINED' },
    ]);
    expect(writes).toEqual([]);
  });

  it('nothing to change is a no-op', async () => {
    const { call, writes } = setup(WITH_USER);
    expect(
      await call('unifi_update_firewall_policy', {
        policy: 'dmz-out',
        action: 'BLOCK',
        confirm: true,
      }),
    ).toEqual({
      unchanged: true,
      policy: 'dmz-out',
    });
    expect(writes).toEqual([]);
  });
});

describe('unifi_set_firewall_policy_enabled', () => {
  it('is easy for a policy that reaches nothing protected', async () => {
    const { call, writes } = setup(WITH_USER);
    const out = await call('unifi_set_firewall_policy_enabled', {
      policy: 'dmz-out',
      enabled: false,
    });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: POLICY_PATH(DMZ_OUT.id as string),
        body: expect.objectContaining({ enabled: false, name: 'dmz-out' }),
      },
    ]);
    expect(out).toEqual({
      changed: 'disabled',
      policy: 'dmz-out',
      rule: 'Dmz → External: BLOCK all "dmz-out" (disabled)',
    });
  });

  it('is confirm-level for an Internal-zone policy (R19)', async () => {
    const { call, writes } = setup(WITH_USER);
    const out = (await call('unifi_set_firewall_policy_enabled', {
      policy: 'lan-out',
      enabled: true,
    })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toContain('pi-cluster');
  });

  it('already in that state is a no-op', async () => {
    const { call, writes } = setup(WITH_USER);
    expect(
      await call('unifi_set_firewall_policy_enabled', { policy: 'dmz-out', enabled: true }),
    ).toEqual({
      unchanged: true,
      policy: 'dmz-out',
      enabled: true,
    });
    expect(writes).toEqual([]);
  });

  it('refuses a system-defined policy', async () => {
    const { call, writes } = setup(WITH_USER);
    await expect(
      call('unifi_set_firewall_policy_enabled', { policy: SYSTEM_POLICY, enabled: false }),
    ).rejects.toThrow('system-defined policy; UniFi manages it');
    expect(writes).toEqual([]);
  });
});

describe('unifi_delete_firewall_policy', () => {
  it('without confirm previews and sends nothing; with confirm sends one DELETE', async () => {
    const first = setup(WITH_USER);
    const out = (await first.call('unifi_delete_firewall_policy', { policy: 'dmz-out' })) as Out;
    expect(first.writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'delete firewall policy',
        policy: 'dmz-out',
        rule: 'Dmz → External: BLOCK all "dmz-out"',
      },
      requires: 'confirm: true',
    });
    const second = setup(WITH_USER);
    await second.call('unifi_delete_firewall_policy', { policy: 'dmz-out', confirm: true });
    expect(second.writes).toEqual([
      { method: 'DELETE', path: POLICY_PATH(DMZ_OUT.id as string), body: undefined },
    ]);
  });

  it('refuses a system-defined policy', async () => {
    const { call, writes } = setup(WITH_USER);
    await expect(
      call('unifi_delete_firewall_policy', { policy: SYSTEM_POLICY, confirm: true }),
    ).rejects.toThrow('system-defined policy; UniFi manages it');
    expect(writes).toEqual([]);
  });
});

describe('unifi_reorder_firewall_policies', () => {
  const second = userPolicy(
    '11111111-0000-4000-8000-000000000005',
    'dmz-out-2',
    ZONES.dmz,
    ZONES.external,
  );
  const pair = (before: Array<string | null>) => ({
    fixtures: {
      'official-firewall-policies': policies(DMZ_OUT, second),
      'official-firewall-policies-ordering': ordering(before),
    },
  });
  const args = {
    sourceZone: 'Dmz',
    destinationZone: 'External',
    beforeSystemDefined: ['dmz-out-2', DMZ_OUT.id],
  };

  it('without confirm previews the order before → after and sends nothing', async () => {
    const { call, writes } = setup(pair([DMZ_OUT.id as string, second.id as string]));
    const out = (await call('unifi_reorder_firewall_policies', args)) as Out;
    expect(writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'reorder firewall policies',
        zones: 'Dmz → External',
        before: { beforeSystemDefined: ['dmz-out', 'dmz-out-2'], afterSystemDefined: [] },
        after: { beforeSystemDefined: ['dmz-out-2', 'dmz-out'], afterSystemDefined: [] },
      },
      requires: 'confirm: true',
    });
  });

  it('with confirm PUTs the new order for that zone pair', async () => {
    const { call, writes } = setup(pair([DMZ_OUT.id as string, second.id as string]));
    await call('unifi_reorder_firewall_policies', { ...args, confirm: true });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${OFFICIAL_SITE}/firewall/policies/ordering`,
        query: { sourceFirewallZoneId: ZONES.dmz, destinationFirewallZoneId: ZONES.external },
        body: {
          orderedFirewallPolicyIds: {
            beforeSystemDefined: [second.id, DMZ_OUT.id],
            afterSystemDefined: [],
          },
        },
      },
    ]);
  });

  it('must name every user-defined policy of the pair exactly once', async () => {
    const { call, writes } = setup(pair([DMZ_OUT.id as string, second.id as string]));
    await expect(
      call('unifi_reorder_firewall_policies', {
        ...args,
        beforeSystemDefined: ['dmz-out'],
        confirm: true,
      }),
    ).rejects.toThrow('the new order leaves out dmz-out-2');
    await expect(
      call('unifi_reorder_firewall_policies', {
        ...args,
        beforeSystemDefined: ['dmz-out', 'dmz-out', 'dmz-out-2'],
        confirm: true,
      }),
    ).rejects.toThrow('dmz-out is named twice');
    expect(writes).toEqual([]);
  });

  it('refuses to move a system-defined policy', async () => {
    const { call, writes } = setup(pair([DMZ_OUT.id as string, second.id as string]));
    await expect(
      call('unifi_reorder_firewall_policies', {
        sourceZone: 'Internal',
        destinationZone: 'Internal',
        beforeSystemDefined: [SYSTEM_POLICY],
        confirm: true,
      }),
    ).rejects.toThrow('system-defined policy; UniFi manages it');
    expect(writes).toEqual([]);
  });

  it('refuses a pair holding IPS auto-blocks, which the API cannot name', async () => {
    const { call, writes } = setup(WITH_USER);
    await expect(
      call('unifi_reorder_firewall_policies', {
        sourceZone: 'External',
        destinationZone: 'External',
        beforeSystemDefined: [],
        confirm: true,
      }),
    ).rejects.toThrow(/8 of its user-defined policies have no id/);
    expect(writes).toEqual([]);
  });

  it('an Internal pair warns about pi-cluster', async () => {
    const lan2 = userPolicy(
      '11111111-0000-4000-8000-000000000006',
      'lan-out-2',
      ZONES.internal,
      ZONES.external,
    );
    const { call } = setup({
      fixtures: {
        'official-firewall-policies': policies(LAN_OUT, lan2),
        'official-firewall-policies-ordering': ordering([LAN_OUT.id as string, lan2.id as string]),
      },
    });
    const out = (await call('unifi_reorder_firewall_policies', {
      sourceZone: 'Internal',
      destinationZone: 'External',
      beforeSystemDefined: ['lan-out-2', 'lan-out'],
    })) as Out;
    expect(out.warning).toContain('pi-cluster');
  });
});

describe('firewall zones', () => {
  const custom = {
    id: '33333333-0000-4000-8000-000000000001',
    name: 'Lab',
    networkIds: [NETS.iot],
    metadata: { origin: 'USER_DEFINED' },
  };
  const withCustom = { fixtures: { 'official-firewall-zones': zones(custom) } };
  const ZONE_PATH = `${OFFICIAL_SITE}/firewall/zones`;

  it('create is easy for networks that are not protected: networks by name', async () => {
    const { call, writes } = setup(created);
    const out = await call('unifi_create_firewall_zone', { name: 'IoT zone', networks: ['IoT'] });
    expect(writes).toEqual([
      { method: 'POST', path: ZONE_PATH, body: { name: 'IoT zone', networkIds: [NETS.iot] } },
    ]);
    expect(out).toEqual({
      changed: 'created',
      zone: { id: '22222222-0000-4000-8000-000000000009', name: 'IoT zone', networks: ['IoT'] },
    });
  });

  it('create with pi-cluster is confirm-level', async () => {
    const { call, writes } = setup(created);
    const out = (await call('unifi_create_firewall_zone', {
      name: 'k3s',
      networks: ['pi-cluster'],
    })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toContain('pi-cluster, a protected network');
  });

  it('update is confirm-level and PUTs name and networks', async () => {
    const { call, writes } = setup({ ...withCustom });
    const preview = (await call('unifi_update_firewall_zone', {
      zone: 'Lab',
      networks: ['IoT', 'Default'],
    })) as Out;
    expect(preview.requires).toBe('confirm: true');
    expect(writes).toEqual([]);
    await call('unifi_update_firewall_zone', {
      zone: 'lab',
      networks: ['IoT', 'Default'],
      confirm: true,
    });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${ZONE_PATH}/${custom.id}`,
        body: { name: 'Lab', networkIds: [NETS.iot, NETS.default] },
      },
    ]);
  });

  it('moving pi-cluster in or out warns', async () => {
    const { call } = setup(withCustom);
    const out = (await call('unifi_update_firewall_zone', {
      zone: 'Lab',
      networks: ['IoT', 'pi-cluster'],
    })) as Out;
    expect(out.warning).toContain('pi-cluster');
  });

  it('delete is confirm-level', async () => {
    const { call, writes } = setup(withCustom);
    expect(((await call('unifi_delete_firewall_zone', { zone: 'Lab' })) as Out).requires).toBe(
      'confirm: true',
    );
    await call('unifi_delete_firewall_zone', { zone: 'Lab', confirm: true });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${ZONE_PATH}/${custom.id}`, body: undefined },
    ]);
  });

  it('refuses to update or delete a system-defined zone', async () => {
    const { call, writes } = setup(withCustom);
    await expect(
      call('unifi_update_firewall_zone', { zone: 'Internal', name: 'LAN', confirm: true }),
    ).rejects.toThrow('"Internal" is a system-defined zone; UniFi manages it');
    await expect(
      call('unifi_delete_firewall_zone', { zone: 'Dmz', confirm: true }),
    ).rejects.toThrow('system-defined zone; UniFi manages it');
    expect(writes).toEqual([]);
  });

  it('an unknown network is an error that names the networks', async () => {
    const { call } = setup(created);
    await expect(
      call('unifi_create_firewall_zone', { name: 'x', networks: ['Guest'] }),
    ).rejects.toThrow('No network matches "Guest"; the networks are: ');
  });
});

describe('confirm-level firewall tools through the MCP SDK', () => {
  it.each([
    ['unifi_update_firewall_policy', { policy: 'dmz-out', loggingEnabled: true }],
    ['unifi_delete_firewall_policy', { policy: 'dmz-out' }],
    ['unifi_set_firewall_policy_enabled', { policy: 'lan-out', enabled: true }],
    [
      'unifi_create_firewall_policy',
      {
        name: 'x',
        action: 'BLOCK',
        source: { zone: 'Internal' },
        destination: { zone: 'External' },
      },
    ],
  ] as const)('%s refuses every loose confirm', async (name, args) => {
    const { tools, onWrite } = setup(WITH_USER);
    await expectRejectsLooseConfirm(await connect(tools), name, args, onWrite);
  });

  it('unifi_reorder_firewall_policies refuses every loose confirm', async () => {
    const second = userPolicy(
      '11111111-0000-4000-8000-000000000005',
      'dmz-out-2',
      ZONES.dmz,
      ZONES.external,
    );
    const { tools, onWrite } = setup({
      fixtures: {
        'official-firewall-policies': policies(DMZ_OUT, second),
        'official-firewall-policies-ordering': ordering([
          DMZ_OUT.id as string,
          second.id as string,
        ]),
      },
    });
    await expectRejectsLooseConfirm(
      await connect(tools),
      'unifi_reorder_firewall_policies',
      {
        sourceZone: 'Dmz',
        destinationZone: 'External',
        beforeSystemDefined: ['dmz-out-2', 'dmz-out'],
      },
      onWrite,
    );
  });

  it.each([
    ['unifi_create_firewall_zone', { name: 'k3s', networks: ['pi-cluster'] }],
    ['unifi_update_firewall_zone', { zone: 'Lab', name: 'Lab 2' }],
    ['unifi_delete_firewall_zone', { zone: 'Lab' }],
  ] as const)('%s refuses every loose confirm', async (name, args) => {
    const custom = {
      id: '33333333-0000-4000-8000-000000000001',
      name: 'Lab',
      networkIds: [NETS.iot],
      metadata: { origin: 'USER_DEFINED' },
    };
    const { tools, onWrite } = setup({ fixtures: { 'official-firewall-zones': zones(custom) } });
    await expectRejectsLooseConfirm(await connect(tools), name, args, onWrite);
  });
});
