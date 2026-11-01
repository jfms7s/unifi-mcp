import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import {
  LEGACY_SITE,
  OFFICIAL_SITE,
  fakeWriteConsole,
  withAccess,
  type ConsoleOptions,
} from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);

/** client-3: an idle IoT client, 192.168.11.154. */
const CLIENT_3_MAC = '02:00:00:00:00:07';
const CLIENT_3_OFFICIAL = 'a2df06a1-033b-3843-89ba-a57ad15a9fbb';
const WARNING =
  /^This can cut unifi-mcp off from the console: client client-22 \(192\.168\.0\.231\) is on pi-cluster/;

describe('unifi_block_client / unifi_unblock_client / unifi_reconnect_client', () => {
  it.each([
    ['unifi_block_client', 'block-sta', 'blocked'],
    ['unifi_unblock_client', 'unblock-sta', 'unblocked'],
    ['unifi_reconnect_client', 'kick-sta', 'reconnected'],
  ])('%s posts %s to cmd/stamgr with the MAC and names the client', async (tool, cmd, changed) => {
    const { call, writes } = setup();
    const out = await call(tool, { client: 'client-3' });
    expect(writes).toEqual([
      { method: 'POST', path: `${LEGACY_SITE}/cmd/stamgr`, body: { cmd, mac: CLIENT_3_MAC } },
    ]);
    expect(out).toEqual({ changed, client: 'client-3' });
  });

  it('finds the client by IP and by MAC too', async () => {
    const { call, writes } = setup();
    await call('unifi_block_client', { client: '192.168.11.154' });
    await call('unifi_block_client', { client: CLIENT_3_MAC.toUpperCase() });
    expect(writes.map((w) => w.body)).toEqual([
      { cmd: 'block-sta', mac: CLIENT_3_MAC },
      { cmd: 'block-sta', mac: CLIENT_3_MAC },
    ]);
  });

  it('blocking a k3s node without confirm previews with the warning and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_block_client', { client: 'client-22' })) as Record<
      string,
      unknown
    >;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(WARNING);
    expect(out.requires).toBe('confirm: true');
    expect(out.preview).toMatchObject({
      would: 'block',
      client: 'client-22',
      network: 'pi-cluster',
    });
  });

  it('kicking a k3s node found by IP is guarded the same way', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_reconnect_client', { client: '192.168.0.231' })) as Record<
      string,
      unknown
    >;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(WARNING);
  });

  it('with confirm: true it blocks the k3s node and repeats the warning', async () => {
    const { call, writes } = setup();
    const out = await call('unifi_block_client', { client: 'client-22', confirm: true });
    expect(writes).toHaveLength(1);
    expect(writes[0]!.body).toEqual({ cmd: 'block-sta', mac: expect.any(String) });
    expect(out).toEqual({
      changed: 'blocked',
      client: 'client-22',
      warning: expect.stringMatching(WARNING),
    });
  });

  it('unblocking a k3s node is easy: it gives access back', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_unblock_client', { client: 'client-22' })).toEqual({
      changed: 'unblocked',
      client: 'client-22',
    });
    expect(writes).toHaveLength(1);
  });

  it('an ambiguous name returns the candidates and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_block_client', { client: 'data-archive' })) as Record<
      string,
      unknown
    >;
    expect(out).toMatchObject({ ambiguous: true });
    expect(out.candidates).toHaveLength(2);
    expect(writes).toEqual([]);
  });

  it('a partial name is never acted on: it comes back as a candidate', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_block_client', { client: 'Hub' })) as Record<string, unknown>;
    expect(out).toMatchObject({ ambiguous: true });
    expect(out.message).toMatch(/^"Hub" is only part of a name/);
    expect(out.candidates).toEqual([expect.objectContaining({ name: 'MAC Hub' })]);
    expect(writes).toEqual([]);
  });

  it('no match is an error and sends nothing', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_block_client', { client: 'nobody-here' })).rejects.toThrow(
      'No client matches "nobody-here"',
    );
    expect(writes).toEqual([]);
  });

  it('through the SDK, a loose confirm on a k3s node never kicks it', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_reconnect_client',
      { client: 'client-22' },
      onWrite,
    );
  });

  it('through the SDK, a loose confirm on a k3s node never blocks it', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(client, 'unifi_block_client', { client: 'client-22' }, onWrite);
    const r = await client.callTool({
      name: 'unifi_block_client',
      arguments: { client: 'client-22', confirm: true },
    });
    expect(r.isError).toBeFalsy();
    expect(onWrite).toHaveBeenCalledOnce();
  });
});

describe('unifi_authorize_guest / unifi_unauthorize_guest', () => {
  const guest = { fixtures: { 'official-clients': withAccess('client-3', 'GUEST') } };
  const ACTIONS = `${OFFICIAL_SITE}/clients/${CLIENT_3_OFFICIAL}/actions`;

  it('authorize posts the official action with every limit, by official id', async () => {
    const { call, writes } = setup({
      ...guest,
      officialReply: {
        action: 'AUTHORIZE_GUEST_ACCESS',
        grantedAuthorization: {
          authorizationMethod: 'API',
          authorizedAt: '2026-11-01T10:00:00Z',
          expiresAt: '2026-11-01T11:00:00Z',
        },
      },
    });
    const out = await call('unifi_authorize_guest', {
      client: 'client-3',
      minutes: 60,
      dataLimitMb: 500,
      rxKbps: 2000,
      txKbps: 1000,
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: ACTIONS,
        body: {
          action: 'AUTHORIZE_GUEST_ACCESS',
          timeLimitMinutes: 60,
          dataUsageLimitMBytes: 500,
          rxRateLimitKbps: 2000,
          txRateLimitKbps: 1000,
        },
      },
    ]);
    expect(out).toEqual({
      changed: 'guest authorized',
      client: 'client-3',
      expiresAt: '2026-11-01T11:00:00Z',
    });
  });

  it('authorize without limits sends only the action', async () => {
    const { call, writes } = setup(guest);
    expect(await call('unifi_authorize_guest', { client: 'client-3' })).toEqual({
      changed: 'guest authorized',
      client: 'client-3',
    });
    expect(writes).toEqual([
      { method: 'POST', path: ACTIONS, body: { action: 'AUTHORIZE_GUEST_ACCESS' } },
    ]);
  });

  it('unauthorize posts UNAUTHORIZE_GUEST_ACCESS', async () => {
    const { call, writes } = setup(guest);
    expect(await call('unifi_unauthorize_guest', { client: 'client-3' })).toEqual({
      changed: 'guest unauthorized',
      client: 'client-3',
    });
    expect(writes).toEqual([
      { method: 'POST', path: ACTIONS, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } },
    ]);
  });

  it('limits outside the API ranges are refused before anything is sent', async () => {
    const { call, writes } = setup(guest);
    for (const bad of [
      { minutes: 0 },
      { dataLimitMb: 1_048_577 },
      { rxKbps: 1 },
      { txKbps: 100_001 },
      { minutes: 1.5 },
    ]) {
      await expect(call('unifi_authorize_guest', { client: 'client-3', ...bad })).rejects.toThrow();
    }
    expect(writes).toEqual([]);
  });

  it.each(['unifi_authorize_guest', 'unifi_unauthorize_guest'])(
    '%s on a client the official API does not know is a clear error, nothing sent',
    async (tool) => {
      const { call, writes } = setup(guest);
      // client-50 is in rest/user only: offline.
      await expect(call(tool, { client: 'client-50' })).rejects.toThrow(
        "client-50 isn't known to the official API; it may be offline",
      );
      expect(writes).toEqual([]);
    },
  );

  describe('with the official client list failing', () => {
    // A body without the page fields: the official read fails as endpoint-changed.
    const down = { fixtures: { 'official-clients': { broken: true } } };

    it.each(['unifi_authorize_guest', 'unifi_unauthorize_guest'])(
      '%s refuses, saying the official API did not answer; nothing sent',
      async (tool) => {
        const { call, writes } = setup(down);
        await expect(call(tool, { client: 'client-3' })).rejects.toThrow(
          /client-3 has no official id: the official client list didn't answer .*guest actions are unavailable until it does/,
        );
        expect(writes).toEqual([]);
      },
    );

    it('a legacy action still runs', async () => {
      const { call, writes } = setup(down);
      expect(await call('unifi_block_client', { client: 'client-3' })).toEqual({
        changed: 'blocked',
        client: 'client-3',
      });
      expect(writes).toHaveLength(1);
    });
  });

  it('a client that is not a guest is refused, nothing sent', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_authorize_guest', { client: 'client-3' })).rejects.toThrow(
      'client-3 is not a guest client (access DEFAULT)',
    );
    expect(writes).toEqual([]);
  });

  it('unauthorizing a guest on pi-cluster is guarded', async () => {
    const { call, writes } = setup({
      fixtures: { 'official-clients': withAccess('client-22 00:1b', 'GUEST') },
    });
    const out = (await call('unifi_unauthorize_guest', { client: 'client-22' })) as Record<
      string,
      unknown
    >;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(WARNING);
  });

  it('authorizing a guest on pi-cluster previews and sends nothing', async () => {
    const { call, writes } = setup({
      fixtures: { 'official-clients': withAccess('client-22 00:1b', 'GUEST') },
    });
    const out = (await call('unifi_authorize_guest', {
      client: 'client-22',
      minutes: 30,
    })) as Record<string, unknown>;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(WARNING);
    expect(out.preview).toMatchObject({
      would: 'authorize guest',
      client: 'client-22',
      minutes: 30,
    });
  });

  it.each(['unifi_authorize_guest', 'unifi_unauthorize_guest'])(
    'through the SDK, %s on a pi-cluster guest refuses every loose confirm',
    async (tool) => {
      const { tools, onWrite } = setup({
        fixtures: { 'official-clients': withAccess('client-22 00:1b', 'GUEST') },
      });
      const client = await connect(tools);
      await expectRejectsLooseConfirm(client, tool, { client: 'client-22' }, onWrite);
    },
  );

  it('an ambiguous name returns the candidates and sends nothing', async () => {
    const { call, writes } = setup(guest);
    const out = await call('unifi_authorize_guest', { client: 'data-archive' });
    expect(out).toMatchObject({ ambiguous: true });
    expect(writes).toEqual([]);
  });
});
