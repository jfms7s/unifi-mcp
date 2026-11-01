import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { WARNING, ZONES, policies, trafficLists, userPolicy } from './firewall-fixtures.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions, type Write } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);

type Out = Record<string, unknown>;

const LIST_ID = '44444444-0000-4000-8000-000000000001';
const listFilter = {
  type: 'IP_ADDRESS',
  ipAddressFilter: {
    type: 'TRAFFIC_MATCHING_LIST',
    matchOpposite: false,
    trafficMatchingListId: LIST_ID,
  },
};
const inbound = userPolicy(
  '44444444-0000-4000-8000-000000000002',
  'unifi-mcp blocklist inbound',
  ZONES.external,
  ZONES.internal,
  {
    source: { zoneId: ZONES.external, trafficFilter: listFilter },
  },
);
const outbound = userPolicy(
  '44444444-0000-4000-8000-000000000003',
  'unifi-mcp blocklist outbound',
  ZONES.internal,
  ZONES.external,
  {
    destination: { zoneId: ZONES.external, trafficFilter: listFilter },
  },
);
const list = (...values: string[]) => ({
  id: LIST_ID,
  name: 'unifi-mcp blocklist',
  type: 'IPV4_ADDRESSES',
  items: values.map((value) => ({ type: value.includes('/') ? 'SUBNET' : 'IP_ADDRESS', value })),
});
/** The console once the blocklist exists, holding `values`. */
const existing = (...values: string[]): ConsoleOptions => ({
  fixtures: {
    'official-traffic-matching-lists': trafficLists(list(...values)),
    'official-firewall-policies': policies(inbound, outbound),
  },
});

const LISTS = `${OFFICIAL_SITE}/traffic-matching-lists`;
const POLICIES = `${OFFICIAL_SITE}/firewall/policies`;

/** Answers each create with an id of its own, so the policies can be checked against the list's. */
const ids = {
  officialReply: (w: Write) =>
    w.path === LISTS
      ? { id: LIST_ID }
      : {
          id: `55555555-0000-4000-8000-00000000000${(w.body as { name: string }).name.endsWith('inbound') ? 1 : 2}`,
        },
};

describe('unifi_block_ip: the first call creates the blocklist', () => {
  it('without confirm previews the three creates and sends nothing', async () => {
    const { call, writes } = setup(ids);
    const out = (await call('unifi_block_ip', { ip: '198.51.100.7', reason: 'scanner' })) as Out;
    expect(writes).toEqual([]);
    expect(out.requires).toBe('confirm: true');
    expect(out.warning).toBeUndefined();
    expect(out.preview).toEqual({
      would: 'create the unifi-mcp blocklist, then block 198.51.100.7',
      reason: 'scanner',
      create: [
        'traffic matching list "unifi-mcp blocklist" (IPv4 addresses): 198.51.100.7',
        'policy "unifi-mcp blocklist inbound": External → Internal: BLOCK from list "unifi-mcp blocklist"',
        'policy "unifi-mcp blocklist outbound": Internal → External: BLOCK to list "unifi-mcp blocklist"',
      ],
    });
  });

  it('with confirm creates them in order: list, inbound, outbound', async () => {
    const { call, writes } = setup(ids);
    const out = (await call('unifi_block_ip', { ip: '198.51.100.7', confirm: true })) as Out;
    expect(writes).toEqual([
      {
        method: 'POST',
        path: LISTS,
        body: {
          name: 'unifi-mcp blocklist',
          type: 'IPV4_ADDRESSES',
          items: [{ type: 'IP_ADDRESS', value: '198.51.100.7' }],
        },
      },
      {
        method: 'POST',
        path: POLICIES,
        body: {
          name: 'unifi-mcp blocklist inbound',
          description:
            'Managed by unifi-mcp: traffic from the addresses in the unifi-mcp blocklist',
          enabled: true,
          action: { type: 'BLOCK' },
          source: { zoneId: ZONES.external, trafficFilter: listFilter },
          destination: { zoneId: ZONES.internal },
          ipProtocolScope: { ipVersion: 'IPV4' },
          loggingEnabled: false,
        },
      },
      {
        method: 'POST',
        path: POLICIES,
        body: {
          name: 'unifi-mcp blocklist outbound',
          description: 'Managed by unifi-mcp: traffic to the addresses in the unifi-mcp blocklist',
          enabled: true,
          action: { type: 'BLOCK' },
          source: { zoneId: ZONES.internal },
          destination: { zoneId: ZONES.external, trafficFilter: listFilter },
          ipProtocolScope: { ipVersion: 'IPV4' },
          loggingEnabled: false,
        },
      },
    ]);
    expect(out).toMatchObject({
      changed: 'blocked',
      ip: '198.51.100.7',
      created: ['list', 'inbound', 'outbound'],
    });
  });

  it('a CIDR becomes a SUBNET item', async () => {
    const { call, writes } = setup(ids);
    await call('unifi_block_ip', { ip: '203.0.113.0/24', confirm: true });
    expect(writes[0]!.body).toMatchObject({ items: [{ type: 'SUBNET', value: '203.0.113.0/24' }] });
  });

  it('creates only what is missing: a list without its policies gets the IP and the two policies', async () => {
    const { call, writes } = setup({
      ...ids,
      fixtures: { 'official-traffic-matching-lists': trafficLists(list('198.51.100.1')) },
    });
    const out = (await call('unifi_block_ip', { ip: '198.51.100.7' })) as Out;
    expect((out.preview as Out).create).toHaveLength(2);
    await call('unifi_block_ip', { ip: '198.51.100.7', confirm: true });
    expect(writes.map((w) => `${w.method} ${w.path} ${(w.body as { name: string }).name}`)).toEqual(
      [
        `PUT ${LISTS}/${LIST_ID} unifi-mcp blocklist`,
        `POST ${POLICIES} unifi-mcp blocklist inbound`,
        `POST ${POLICIES} unifi-mcp blocklist outbound`,
      ],
    );
  });
});

describe('unifi_block_ip once the blocklist exists', () => {
  it('is easy: one PUT of the list with the IP appended', async () => {
    const { call, writes } = setup(existing('198.51.100.1'));
    const out = await call('unifi_block_ip', { ip: '198.51.100.7' });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${LISTS}/${LIST_ID}`,
        body: {
          name: 'unifi-mcp blocklist',
          type: 'IPV4_ADDRESSES',
          items: [
            { type: 'IP_ADDRESS', value: '198.51.100.1' },
            { type: 'IP_ADDRESS', value: '198.51.100.7' },
          ],
        },
      },
    ]);
    expect(out).toEqual({ changed: 'blocked', ip: '198.51.100.7', blocklist: 2 });
  });

  it('an IP already listed is a no-op that says so', async () => {
    const { call, writes } = setup(existing('198.51.100.1', '198.51.100.7'));
    expect(await call('unifi_block_ip', { ip: '198.51.100.7' })).toEqual({
      unchanged: true,
      ip: '198.51.100.7',
      note: '198.51.100.7 is already in the unifi-mcp blocklist',
    });
    expect(writes).toEqual([]);
  });

  it('an IP inside pi-cluster (192.168.0.0/24) is confirm-level', async () => {
    const { call, writes } = setup(existing('198.51.100.1'));
    const out = (await call('unifi_block_ip', { ip: '192.168.0.17' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBe(
      `${WARNING} 192.168.0.17 is inside pi-cluster (192.168.0.0/24), a protected network`,
    );
    expect(out.requires).toBe('confirm: true');
  });

  it('a subnet that overlaps pi-cluster is confirm-level too', async () => {
    const { call, writes } = setup(existing('198.51.100.1'));
    const out = (await call('unifi_block_ip', { ip: '192.168.0.0/16' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toContain('pi-cluster');
  });

  it('says when a blocklist policy is disabled', async () => {
    const off = { ...inbound, enabled: false };
    const { call } = setup({
      fixtures: {
        'official-traffic-matching-lists': trafficLists(list('198.51.100.1')),
        'official-firewall-policies': policies(off, outbound),
      },
    });
    const out = (await call('unifi_block_ip', { ip: '198.51.100.7' })) as Out;
    expect(out.note).toBe(
      '"unifi-mcp blocklist inbound" is disabled, so that direction is not blocked',
    );
  });
});

describe('unifi_unblock_ip', () => {
  it('removes the IP with one PUT', async () => {
    const { call, writes } = setup(existing('198.51.100.1', '198.51.100.7'));
    const out = await call('unifi_unblock_ip', { ip: '198.51.100.7' });
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${LISTS}/${LIST_ID}`,
        body: {
          name: 'unifi-mcp blocklist',
          type: 'IPV4_ADDRESSES',
          items: [{ type: 'IP_ADDRESS', value: '198.51.100.1' }],
        },
      },
    ]);
    expect(out).toEqual({ changed: 'unblocked', ip: '198.51.100.7', blocklist: 1 });
  });

  it('an IP not listed, or no blocklist at all, is a no-op that says so', async () => {
    const listed = setup(existing('198.51.100.1'));
    expect(await listed.call('unifi_unblock_ip', { ip: '198.51.100.7' })).toEqual({
      unchanged: true,
      ip: '198.51.100.7',
      note: '198.51.100.7 is not in the unifi-mcp blocklist',
    });
    const none = setup();
    expect(await none.call('unifi_unblock_ip', { ip: '198.51.100.7' })).toMatchObject({
      unchanged: true,
    });
    expect([...listed.writes, ...none.writes]).toEqual([]);
  });

  it('the last IP: the list cannot be empty, so it is confirm-level and removes the blocklist', async () => {
    const { call, writes } = setup(existing('198.51.100.7'));
    const out = (await call('unifi_unblock_ip', { ip: '198.51.100.7' })) as Out;
    expect(writes).toEqual([]);
    expect(out.preview).toMatchObject({
      would:
        'unblock 198.51.100.7, the last address: delete the unifi-mcp blocklist (both policies, then the list)',
    });
    await call('unifi_unblock_ip', { ip: '198.51.100.7', confirm: true });
    expect(writes.map((w) => `${w.method} ${w.path}`)).toEqual([
      `DELETE ${POLICIES}/${outbound.id}`,
      `DELETE ${POLICIES}/${inbound.id}`,
      `DELETE ${LISTS}/${LIST_ID}`,
    ]);
  });

  it('a pi-cluster address is confirm-level', async () => {
    const { call, writes } = setup(existing('198.51.100.1', '192.168.0.17'));
    const out = (await call('unifi_unblock_ip', { ip: '192.168.0.17' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toContain('pi-cluster');
  });
});

describe('the ip input', () => {
  it.each(['example.com', '300.1.1.1', '2001:db8::1', '198.51.100.7/33', ''])(
    'refuses %j',
    async (ip) => {
      const { tools, onWrite } = setup();
      const client = await connect(tools);
      for (const name of ['unifi_block_ip', 'unifi_unblock_ip']) {
        const r = await client.callTool({ name, arguments: { ip, confirm: true } });
        expect(r.isError, `${name} ${ip}`).toBe(true);
      }
      expect(onWrite).not.toHaveBeenCalled();
    },
  );
});

describe('blocklist tools through the MCP SDK', () => {
  it('the first unifi_block_ip refuses every loose confirm', async () => {
    const { tools, onWrite } = setup(ids);
    await expectRejectsLooseConfirm(
      await connect(tools),
      'unifi_block_ip',
      { ip: '198.51.100.7' },
      onWrite,
    );
  });

  it('unifi_block_ip on a pi-cluster address refuses every loose confirm', async () => {
    const { tools, onWrite } = setup(existing('198.51.100.1'));
    await expectRejectsLooseConfirm(
      await connect(tools),
      'unifi_block_ip',
      { ip: '192.168.0.17' },
      onWrite,
    );
  });

  it('unifi_unblock_ip of the last address refuses every loose confirm', async () => {
    const { tools, onWrite } = setup(existing('198.51.100.7'));
    await expectRejectsLooseConfirm(
      await connect(tools),
      'unifi_unblock_ip',
      { ip: '198.51.100.7' },
      onWrite,
    );
  });
});
