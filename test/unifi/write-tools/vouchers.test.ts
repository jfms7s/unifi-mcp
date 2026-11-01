import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();

const V1 = 'cccccccc-0000-4000-8000-000000000001';
const V2 = 'cccccccc-0000-4000-8000-000000000002';

const voucher = (id: string, name: string, expired = false) => ({
  id,
  name,
  code: id === V1 ? '1234567890' : '0987654321',
  createdAt: '2026-11-01T10:00:00Z',
  expired,
  timeLimitMinutes: 60,
  authorizedGuestCount: 0,
  authorizedGuestLimit: 1,
});

const VOUCHERS = {
  'official-hotspot-vouchers': {
    offset: 0,
    limit: 200,
    count: 2,
    totalCount: 2,
    data: [voucher(V1, 'party'), voucher(V2, 'party', true)],
  },
};

const setup = (opts: ConsoleOptions = {}) =>
  fakeWriteConsole(server, { ...opts, fixtures: { ...VOUCHERS, ...opts.fixtures } });

type Out = Record<string, unknown>;

describe('unifi_create_vouchers', () => {
  it('is easy: posts the request and returns the codes', async () => {
    const { call, writes } = setup({ officialReply: { vouchers: [voucher(V1, 'party')] } });
    const out = await call('unifi_create_vouchers', {
      name: 'party',
      timeLimitMinutes: 60,
      count: 1,
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/hotspot/vouchers`,
        body: { name: 'party', timeLimitMinutes: 60, count: 1 },
      },
    ]);
    expect(out).toEqual({
      changed: 'created',
      vouchers: [
        {
          id: V1,
          name: 'party',
          code: '1234567890',
          timeLimitMinutes: 60,
          authorizedGuestLimit: 1,
        },
      ],
    });
  });
});

describe('unifi_delete_voucher', () => {
  it('is easy: one DELETE by id, no confirm needed', async () => {
    const { call, writes } = setup({ officialReply: { vouchersDeleted: 1 } });
    expect(await call('unifi_delete_voucher', { voucherId: V1 })).toEqual({
      changed: 'deleted',
      vouchersDeleted: 1,
    });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${OFFICIAL_SITE}/hotspot/vouchers/${V1}`, body: undefined },
    ]);
  });
});

describe('unifi_delete_vouchers (bulk)', () => {
  it('is confirm-level: without confirm it lists what the filter matches and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_delete_vouchers', { ids: [V1, V2] })) as Out;
    expect(writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'delete vouchers',
        filter: `id.in(${V1}, ${V2})`,
        matching: 2,
        vouchers: [
          { id: V1, name: 'party', expired: false, createdAt: '2026-11-01T10:00:00Z' },
          { id: V2, name: 'party', expired: true, createdAt: '2026-11-01T10:00:00Z' },
        ],
      },
      requires: 'confirm: true',
    });
  });

  it('with confirm sends one DELETE with the filter', async () => {
    const { call, writes } = setup({ officialReply: { vouchersDeleted: 2 } });
    expect(
      await call('unifi_delete_vouchers', {
        name: 'bob party-2_b.x',
        expired: true,
        confirm: true,
      }),
    ).toEqual({ changed: 'deleted', vouchersDeleted: 2 });
    expect(writes).toEqual([
      {
        method: 'DELETE',
        path: `${OFFICIAL_SITE}/hotspot/vouchers`,
        body: undefined,
        query: { filter: "and(name.eq('bob party-2_b.x'), expired.eq(true))" },
      },
    ]);
  });

  it('refuses an empty filter rather than deleting everything', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_delete_vouchers', { confirm: true })).rejects.toThrow(
      /at least one of ids, name or expired/,
    );
    expect(writes).toEqual([]);
  });

  it('refuses a name outside letters, digits, space, - _ . (no quote escaping to get wrong)', async () => {
    const { call, writes } = setup();
    for (const name of ["bob's party", "x'), or(id.isNotNull()", 'a*b', 'naïve\\']) {
      await expect(call('unifi_delete_vouchers', { name, confirm: true }), name).rejects.toThrow(
        /letters, digits, spaces, - _ and \./,
      );
    }
    expect(writes).toEqual([]);
  });

  it('refuses ids that are not UUIDs (no filter injection)', async () => {
    const { call, writes } = setup();
    await expect(
      call('unifi_delete_vouchers', { ids: ['x) , or(id.isNotNull('] }),
    ).rejects.toThrow();
    expect(writes).toEqual([]);
  });

  it('refuses through the MCP SDK every loose confirm', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(client, 'unifi_delete_vouchers', { expired: true }, onWrite);
  });
});
