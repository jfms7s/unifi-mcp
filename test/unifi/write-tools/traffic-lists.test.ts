import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { WARNING, ZONES, policies, trafficLists, userPolicy } from './firewall-fixtures.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);
type Out = Record<string, unknown>;

const LISTS = `${OFFICIAL_SITE}/traffic-matching-lists`;
const SCANNERS = {
  id: '88888888-0000-4000-8000-000000000001',
  name: 'scanners',
  type: 'IPV4_ADDRESSES',
  items: [{ type: 'IP_ADDRESS', value: '198.51.100.1' }],
};
const USER = userPolicy(
  '88888888-0000-4000-8000-000000000002',
  'no-scanners',
  ZONES.external,
  ZONES.internal,
  {
    source: {
      zoneId: ZONES.external,
      trafficFilter: {
        type: 'IP_ADDRESS',
        ipAddressFilter: {
          type: 'TRAFFIC_MATCHING_LIST',
          matchOpposite: false,
          trafficMatchingListId: SCANNERS.id,
        },
      },
    },
  },
);
const withList = {
  fixtures: {
    'official-traffic-matching-lists': trafficLists(SCANNERS),
    'official-firewall-policies': policies(USER),
  },
};
const ip = (value: string) => ({ type: 'IP_ADDRESS', value });

describe('traffic matching lists', () => {
  it('create is easy: an unused list changes nothing', async () => {
    const { call, writes } = setup({ officialReply: { id: SCANNERS.id } });
    const out = await call('unifi_create_traffic_list', {
      name: 'k3s',
      type: 'IPV4_ADDRESSES',
      items: [ip('192.168.0.10')],
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: LISTS,
        body: { name: 'k3s', type: 'IPV4_ADDRESSES', items: [ip('192.168.0.10')] },
      },
    ]);
    expect(out).toEqual({
      changed: 'created',
      trafficList: { id: SCANNERS.id, name: 'k3s', items: 1 },
    });
  });

  it('update is confirm-level, names the policies that use it, and PUTs the whole list', async () => {
    const { call, writes } = setup(withList);
    const preview = (await call('unifi_update_traffic_list', {
      trafficList: 'scanners',
      items: [ip('198.51.100.1'), ip('198.51.100.2')],
    })) as Out;
    expect(writes).toEqual([]);
    expect(preview.warning).toBeUndefined();
    expect(preview.preview).toMatchObject({
      would: 'update traffic matching list',
      trafficList: 'scanners',
      usedBy: ['no-scanners'],
    });
    await call('unifi_update_traffic_list', {
      trafficList: 'scanners',
      items: [ip('198.51.100.1'), ip('198.51.100.2')],
      confirm: true,
    });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${LISTS}/${SCANNERS.id}`,
        body: {
          name: 'scanners',
          type: 'IPV4_ADDRESSES',
          items: [ip('198.51.100.1'), ip('198.51.100.2')],
        },
      },
    ]);
  });

  it('adding or removing a pi-cluster address warns', async () => {
    const { call } = setup(withList);
    const out = (await call('unifi_update_traffic_list', {
      trafficList: 'scanners',
      items: [ip('198.51.100.1'), ip('192.168.0.9')],
    })) as Out;
    expect(out.warning).toContain(
      `${WARNING} the policy's source matches 192.168.0.9, inside pi-cluster`,
    );
  });

  it('delete is confirm-level', async () => {
    const { call, writes } = setup(withList);
    const out = (await call('unifi_delete_traffic_list', { trafficList: 'scanners' })) as Out;
    expect(out.preview).toMatchObject({
      would: 'delete traffic matching list',
      usedBy: ['no-scanners'],
    });
    await call('unifi_delete_traffic_list', { trafficList: 'scanners', confirm: true });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${LISTS}/${SCANNERS.id}`, body: undefined },
    ]);
  });

  it.each([
    ['unifi_update_traffic_list', { trafficList: 'scanners', name: 'scanners 2' }],
    ['unifi_delete_traffic_list', { trafficList: 'scanners' }],
  ] as const)('%s refuses every loose confirm through the SDK', async (name, args) => {
    const { tools, onWrite } = setup(withList);
    await expectRejectsLooseConfirm(await connect(tools), name, args, onWrite);
  });
});
