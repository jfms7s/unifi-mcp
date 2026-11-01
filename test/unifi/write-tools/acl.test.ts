import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { NETS, WARNING, aclRules } from './firewall-fixtures.js';
import { without } from './firewall-fixtures.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);
type Out = Record<string, unknown>;

const ACL = `${OFFICIAL_SITE}/acl-rules`;
const created = { officialReply: { id: '66666666-0000-4000-8000-000000000009' } };
const rule = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  type: 'IPV4',
  action: 'BLOCK',
  enabled: true,
  index: 0,
  sourceFilter: { type: 'NETWORKS', networkIds: [NETS.iot] },
  destinationFilter: { type: 'NETWORKS', networkIds: [NETS.default] },
  metadata: { origin: 'USER_DEFINED' },
  ...extra,
});
const IOT_TO_LAN = rule('66666666-0000-4000-8000-000000000001', 'iot-to-lan');
const DERIVED = rule('66666666-0000-4000-8000-000000000002', 'derived', {
  metadata: { origin: 'DERIVED' },
});
const withRules = { fixtures: { 'official-acl-rules': aclRules(IOT_TO_LAN, DERIVED) } };

describe('unifi_create_acl_rule', () => {
  it('is easy between networks that are not protected', async () => {
    const { call, writes } = setup(created);
    const out = await call('unifi_create_acl_rule', {
      name: 'iot-to-lan',
      action: 'BLOCK',
      sourceFilter: { type: 'NETWORKS', networkIds: [NETS.iot] },
      destinationFilter: { type: 'NETWORKS', networkIds: [NETS.default] },
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: ACL,
        body: {
          type: 'IPV4',
          name: 'iot-to-lan',
          action: 'BLOCK',
          enabled: true,
          sourceFilter: { type: 'NETWORKS', networkIds: [NETS.iot] },
          destinationFilter: { type: 'NETWORKS', networkIds: [NETS.default] },
        },
      },
    ]);
    expect(out).toEqual({
      changed: 'created',
      aclRule: { id: '66666666-0000-4000-8000-000000000009', name: 'iot-to-lan' },
    });
  });

  it('pi-cluster, an address in it, or no filter (any) is confirm-level', async () => {
    for (const filters of [
      { sourceFilter: { type: 'NETWORKS', networkIds: [NETS.piCluster] } },
      {
        destinationFilter: {
          type: 'IP_ADDRESSES_OR_SUBNETS',
          ipAddressesOrSubnets: ['192.168.0.10'],
        },
      },
      {},
      { sourceFilter: { type: 'PORTS', portFilter: [22] } },
      // M3: a network the console does not have can't be placed.
      {
        sourceFilter: { type: 'NETWORKS', networkIds: ['99999999-0000-4000-8000-000000000000'] },
        destinationFilter: { type: 'NETWORKS', networkIds: [NETS.iot] },
      },
    ]) {
      const { call, writes } = setup(created);
      const out = (await call('unifi_create_acl_rule', {
        name: 'x',
        action: 'BLOCK',
        ...filters,
      })) as Out;
      expect(writes, JSON.stringify(filters)).toEqual([]);
      expect(out.warning, JSON.stringify(filters)).toContain(WARNING);
    }
  });
});

describe('unifi_update_acl_rule and unifi_delete_acl_rule', () => {
  it('update is confirm-level and PUTs the merged rule without id, metadata and index', async () => {
    const { call, writes } = setup(withRules);
    const preview = (await call('unifi_update_acl_rule', {
      aclRule: 'iot-to-lan',
      action: 'ALLOW',
    })) as Out;
    expect(preview).toEqual({
      preview: {
        would: 'update ACL rule',
        aclRule: 'iot-to-lan',
        changes: { action: { before: 'BLOCK', after: 'ALLOW' } },
      },
      requires: 'confirm: true',
    });
    await call('unifi_update_acl_rule', { aclRule: 'iot-to-lan', action: 'ALLOW', confirm: true });
    const rest = without(IOT_TO_LAN, 'id', 'metadata', 'index');
    expect(writes).toEqual([
      { method: 'PUT', path: `${ACL}/${IOT_TO_LAN.id}`, body: { ...rest, action: 'ALLOW' } },
    ]);
  });

  it('delete is confirm-level', async () => {
    const { call, writes } = setup(withRules);
    expect(((await call('unifi_delete_acl_rule', { aclRule: 'iot-to-lan' })) as Out).requires).toBe(
      'confirm: true',
    );
    await call('unifi_delete_acl_rule', { aclRule: IOT_TO_LAN.id, confirm: true });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${ACL}/${IOT_TO_LAN.id}`, body: undefined },
    ]);
  });

  it('refuses rules UniFi made (not USER_DEFINED)', async () => {
    const { call, writes } = setup(withRules);
    await expect(
      call('unifi_update_acl_rule', { aclRule: 'derived', enabled: false, confirm: true }),
    ).rejects.toThrow('"derived" is a derived ACL rule; UniFi manages it');
    await expect(
      call('unifi_delete_acl_rule', { aclRule: 'derived', confirm: true }),
    ).rejects.toThrow('UniFi manages it');
    expect(writes).toEqual([]);
  });

  it('an unknown rule is an error', async () => {
    const { call } = setup();
    await expect(call('unifi_delete_acl_rule', { aclRule: 'nope', confirm: true })).rejects.toThrow(
      'No ACL rule matches "nope"; the console has no ACL rules',
    );
  });

  it.each([
    ['unifi_update_acl_rule', { aclRule: 'iot-to-lan', enabled: false }],
    ['unifi_delete_acl_rule', { aclRule: 'iot-to-lan' }],
    ['unifi_create_acl_rule', { name: 'x', action: 'BLOCK' }],
  ] as const)('%s refuses every loose confirm through the SDK', async (name, args) => {
    const { tools, onWrite } = setup({ ...withRules, ...created });
    await expectRejectsLooseConfirm(await connect(tools), name, args, onWrite);
  });
});
