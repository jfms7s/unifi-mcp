import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { UnifiApiError } from '../../../src/http/errors.js';
import { liveFixture } from '../../fixtures/live.js';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { BASE, useServer } from '../helpers.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions, type Write } from './harness.js';

const server = useServer();

const IOT = 'f1b4fdb6-c787-4421-92bb-56d55e0ea95a';
const PI_CLUSTER = '80ec407d-e455-4a87-8b26-846881ebf07f';
const SSID_1 = '27c0eae9-ecaf-467f-9a42-bd05f8984bcd';
const SSID_2 = '761e53dc-ee9e-4fe5-91ab-5a6841885093';
const SSID_3 = 'e0077cb0-b9dd-4d24-a1f8-8b9a98c113ea';
const WARNING = 'This can cut unifi-mcp off from the console:';
const OLD_PASS = 'old-secret-passphrase';
const NEW_PASS = 'new-secret-passphrase';

type Out = Record<string, unknown>;
type Row = Record<string, unknown> & { id: string; metadata: unknown };

/** The live list, with ssid-3 moved onto pi-cluster (the live console has none there). */
function rows(): Row[] {
  const page = structuredClone(liveFixture('official-wifi-broadcasts')) as { data: Row[] };
  const ssid3 = page.data.find((r) => r.id === SSID_3)!;
  ssid3.network = { type: 'SPECIFIC', networkId: PI_CLUSTER };
  return page.data;
}

/** GET /wifi/broadcasts/{id}: the list row plus what only the detail carries, passphrase included. */
const detail = (row: Row) => ({
  ...row,
  securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: OLD_PASS, pmfMode: 'OPTIONAL' },
  hideName: false,
  clientIsolationEnabled: false,
  multicastToUnicastConversionEnabled: false,
  uapsdEnabled: false,
  channel2gLockedTo6: false,
  dtimPeriod2gLockedTo3: false,
  advertiseDeviceName: false,
  arpProxyEnabled: false,
  bssTransitionEnabled: true,
});

function setup(opts: ConsoleOptions = {}) {
  const list = rows();
  const fixtures: Record<string, unknown> = {
    'official-wifi-broadcasts': { offset: 0, limit: 200, count: 3, totalCount: 3, data: list },
  };
  for (const r of list) fixtures[`official-wifi-broadcasts-${r.id}`] = detail(r);
  return fakeWriteConsole(server, { ...opts, fixtures: { ...fixtures, ...opts.fixtures } });
}

/** The console answers a PUT or POST with the stored object, passphrase and all. */
const echo = (w: Write) => ({
  id: SSID_2,
  metadata: { origin: 'USER_DEFINED' },
  ...(w.body as object),
});

const noSecrets = (value: unknown) => {
  const text = JSON.stringify(value);
  expect(text).not.toContain(OLD_PASS);
  expect(text).not.toContain(NEW_PASS);
};

describe('unifi_create_wifi', () => {
  it('is easy: posts the request and never echoes the passphrase', async () => {
    const { call, writes } = setup({ officialReply: echo });
    const out = await call('unifi_create_wifi', {
      name: 'guest-wifi',
      type: 'STANDARD',
      enabled: true,
      securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: NEW_PASS },
      network: { type: 'SPECIFIC', networkId: IOT },
      hideName: false,
      clientIsolationEnabled: true,
      multicastToUnicastConversionEnabled: false,
      uapsdEnabled: false,
      broadcastingFrequenciesGHz: [2.4, 5],
    });
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({
      method: 'POST',
      path: `${OFFICIAL_SITE}/wifi/broadcasts`,
      body: { name: 'guest-wifi', securityConfiguration: { passphrase: NEW_PASS } },
    });
    expect(out).toEqual({ changed: 'created', wifi: { id: SSID_2, name: 'guest-wifi' } });
    noSecrets(out);
  });
});

describe('unifi_update_wifi', () => {
  it('is confirm-level: the preview diff lists only changed fields and says only "changed" for the passphrase', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_update_wifi', {
      wifi: 'ssid-2',
      hideName: true,
      securityConfiguration: { passphrase: NEW_PASS },
    })) as Out;
    expect(writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'update wifi',
        wifi: 'ssid-2',
        changes: {
          hideName: { before: false, after: true },
          'securityConfiguration.passphrase': 'changed',
        },
      },
      requires: 'confirm: true',
    });
    noSecrets(out);
  });

  it('with confirm PUTs the whole merged object minus id and metadata; the result has no passphrase', async () => {
    const { call, writes } = setup({ officialReply: echo });
    const out = await call('unifi_update_wifi', {
      wifi: SSID_2,
      securityConfiguration: { passphrase: NEW_PASS },
      confirm: true,
    });
    const rest: Partial<ReturnType<typeof detail>> = detail(rows().find((r) => r.id === SSID_2)!);
    delete rest.id;
    delete rest.metadata;
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${OFFICIAL_SITE}/wifi/broadcasts/${SSID_2}`,
        body: {
          ...rest,
          securityConfiguration: {
            type: 'WPA2_PERSONAL',
            passphrase: NEW_PASS,
            pmfMode: 'OPTIONAL',
          },
        },
      },
    ]);
    expect(out).toEqual({
      changed: 'updated',
      wifi: 'ssid-2',
      fields: ['securityConfiguration.passphrase'],
    });
    noSecrets(out);
  });

  it('a passphrase is redacted from a non-secret field that carries one (pre-shared keys)', async () => {
    const { call } = setup();
    const out = await call('unifi_update_wifi', {
      wifi: 'ssid-2',
      securityConfiguration: {
        presharedKeys: [{ network: { type: 'SPECIFIC', networkId: IOT }, passphrase: NEW_PASS }],
      },
    });
    noSecrets(out);
    expect(JSON.stringify(out)).toContain('<redacted>');
  });

  it('a console error that echoes the passphrase is redacted', async () => {
    const { call } = setup();
    server.use(
      http.put(`${BASE}/proxy/network/integration/*`, () =>
        HttpResponse.json({ message: `passphrase ${NEW_PASS} is weak` }, { status: 400 }),
      ),
    );
    const err = await call('unifi_update_wifi', {
      wifi: 'ssid-2',
      securityConfiguration: { passphrase: NEW_PASS },
      confirm: true,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/400/);
    expect((err as Error).message).not.toContain(NEW_PASS);
  });

  it('withholds the console detail on a failed write carrying a passphrase, keeping status and code', async () => {
    const tricky = 'ab"cd-secret-passphrase';
    const cases = [
      // The raw body is quoted JSON: the passphrase appears escaped (ab\"cd), not verbatim.
      { errors: [{ field: 'passphrase', value: tricky }], code: 'api.err.InvalidPassphrase' },
      // Truncated at the 200-character detail limit, mid-passphrase.
      // The client keeps only `message` here, so there is no api.err code to pass on.
      { message: `${'x'.repeat(190)}${NEW_PASS}`, code: 'HTTP 400)' },
    ];
    for (const body of cases) {
      const { call } = setup();
      server.use(
        http.put(`${BASE}/proxy/network/integration/*`, () =>
          HttpResponse.json(body, { status: 400 }),
        ),
      );
      const err = (await call('unifi_update_wifi', {
        wifi: 'ssid-2',
        securityConfiguration: {
          passphrase: 'value' in (body.errors?.[0] ?? {}) ? tricky : NEW_PASS,
        },
        confirm: true,
      }).catch((e: unknown) => e)) as UnifiApiError;
      expect(err).toBeInstanceOf(UnifiApiError);
      expect(err.kind).toBe('status');
      expect(err.status).toBe(400);
      expect(err.message).toContain('details withheld because the request carried a passphrase');
      expect(err.message).toContain(body.code);
      for (const s of [tricky, 'ab\\"cd', NEW_PASS.slice(0, 10), OLD_PASS]) {
        expect(err.message).not.toContain(s);
        expect(err.detail).not.toContain(s);
      }
    }
  });

  it('refuses to change the broadcast type: delete and recreate instead', async () => {
    const { call, writes } = setup();
    await expect(
      call('unifi_update_wifi', { wifi: 'ssid-2', type: 'IOT_OPTIMIZED', confirm: true }),
    ).rejects.toThrow(/delete and recreate the broadcast to change its type/);
    expect(writes).toEqual([]);
  });

  it('a passphrase that goes away shows as "removed"', async () => {
    const { call } = setup();
    const out = (await call('unifi_update_wifi', {
      wifi: 'ssid-2',
      securityConfiguration: { type: 'OPEN' },
    })) as { preview: { changes: Record<string, unknown> } };
    expect(out.preview.changes['securityConfiguration.passphrase']).toBe('removed');
    noSecrets(out);
  });

  it('live shape: NATIVE with no networkId on a console whose default network is pi-cluster warns', async () => {
    const nets = structuredClone(liveFixture('official-networks')) as {
      data: Array<{ id: string; default: boolean }>;
    };
    for (const n of nets.data) n.default = n.id === PI_CLUSTER;
    const { call } = setup({ fixtures: { 'official-networks': nets } });
    const out = (await call('unifi_update_wifi', { wifi: 'ssid-1', hideName: true })) as Out;
    expect(out.warning).toBe(`${WARNING} it changes pi-cluster, a protected network`);
  });

  it('a network reference it cannot resolve fails closed with a reason', async () => {
    const nets = structuredClone(liveFixture('official-networks')) as {
      data: Array<{ default: boolean }>;
    };
    for (const n of nets.data) n.default = false;
    const unplaced = `${WARNING} can't place broadcast ssid-1's network, so it may serve a protected network`;
    // NATIVE with no default network.
    let out = (await setup({ fixtures: { 'official-networks': nets } }).call('unifi_update_wifi', {
      wifi: 'ssid-1',
      hideName: true,
    })) as Out;
    expect(out.warning).toBe(unplaced);
    // SPECIFIC without a networkId, a missing reference, an unknown type.
    const ssid1 = rows().find((r) => r.id === SSID_1)!;
    for (const network of [{ type: 'SPECIFIC' }, undefined, { type: 'SOMETHING_NEW' }]) {
      const d: Record<string, unknown> = { ...detail(ssid1), network };
      if (network === undefined) delete d.network;
      out = (await setup({
        fixtures: { [`official-wifi-broadcasts-${SSID_1}`]: d },
      }).call('unifi_delete_wifi', { wifi: 'ssid-1' })) as Out;
      expect(out.warning, JSON.stringify(network)).toBe(unplaced);
    }
  });

  it('a broadcast serving pi-cluster carries the lock-out warning', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_update_wifi', { wifi: 'ssid-3', hideName: true })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBe(`${WARNING} it changes pi-cluster, a protected network`);
  });

  it('moving a broadcast onto pi-cluster carries the warning too', async () => {
    const { call } = setup();
    const out = (await call('unifi_update_wifi', {
      wifi: 'ssid-2',
      network: { type: 'SPECIFIC', networkId: PI_CLUSTER },
    })) as Out;
    expect(out.warning).toMatch(/pi-cluster, a protected network/);
  });

  it('a pre-shared key onto pi-cluster makes the broadcast protected', async () => {
    const list = rows();
    const ssid1 = detail(list.find((r) => r.id === SSID_1)!);
    ssid1.securityConfiguration = {
      type: 'WPA2_PERSONAL',
      passphrase: OLD_PASS,
      pmfMode: 'OPTIONAL',
      presharedKeys: [
        { network: { type: 'SPECIFIC', networkId: PI_CLUSTER }, passphrase: OLD_PASS },
      ],
    } as typeof ssid1.securityConfiguration;
    const { call } = setup({ fixtures: { [`official-wifi-broadcasts-${SSID_1}`]: ssid1 } });
    const out = (await call('unifi_delete_wifi', { wifi: 'ssid-1' })) as Out;
    expect(out.warning).toMatch(/pi-cluster, a protected network/);
    noSecrets(out);
  });

  it('an update on an unprotected broadcast has no warning', async () => {
    const { call } = setup();
    const out = (await call('unifi_update_wifi', { wifi: 'ssid-2', hideName: true })) as Out;
    expect(out.warning).toBeUndefined();
    expect(out.requires).toBe('confirm: true');
  });
});

describe('unifi_set_wifi_enabled', () => {
  it('is confirm-level; with confirm it PUTs the whole object with enabled flipped', async () => {
    const { call, writes } = setup();
    const preview = (await call('unifi_set_wifi_enabled', {
      wifi: 'ssid-2',
      enabled: false,
    })) as Out;
    expect(writes).toEqual([]);
    expect(preview).toMatchObject({
      preview: { changes: { enabled: { before: true, after: false } } },
      requires: 'confirm: true',
    });
    noSecrets(preview);

    const out = await call('unifi_set_wifi_enabled', {
      wifi: 'ssid-2',
      enabled: false,
      confirm: true,
    });
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({
      method: 'PUT',
      path: `${OFFICIAL_SITE}/wifi/broadcasts/${SSID_2}`,
      body: { enabled: false, name: 'ssid-2', securityConfiguration: { passphrase: OLD_PASS } },
    });
    expect(writes[0]!.body).not.toHaveProperty('id');
    expect(writes[0]!.body).not.toHaveProperty('metadata');
    expect(out).toEqual({ changed: 'disabled', wifi: 'ssid-2' });
  });

  it('disabling a broadcast on pi-cluster warns of the lock-out', async () => {
    const { call } = setup();
    const out = (await call('unifi_set_wifi_enabled', { wifi: 'ssid-3', enabled: false })) as Out;
    expect(out.warning).toMatch(/pi-cluster, a protected network/);
  });
});

describe('unifi_delete_wifi', () => {
  it('without confirm sends nothing and previews', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_delete_wifi', { wifi: 'ssid-2' })) as Out;
    expect(writes).toEqual([]);
    expect(out).toMatchObject({
      preview: { would: 'delete wifi', wifi: 'ssid-2' },
      requires: 'confirm: true',
    });
    noSecrets(out);
  });

  it('with confirm sends DELETE', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_delete_wifi', { wifi: 'ssid-2', confirm: true })).toEqual({
      changed: 'deleted',
      wifi: 'ssid-2',
    });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${OFFICIAL_SITE}/wifi/broadcasts/${SSID_2}`, body: undefined },
    ]);
  });
});

describe('confirm-level wifi tools through the MCP SDK', () => {
  it('unifi_update_wifi refuses every loose confirm', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_update_wifi',
      { wifi: 'ssid-2', hideName: true },
      onWrite,
    );
    await expectRejectsLooseConfirm(
      client,
      'unifi_update_wifi',
      { wifi: 'ssid-3', hideName: true },
      onWrite,
    );
  });

  it('unifi_set_wifi_enabled refuses every loose confirm', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_set_wifi_enabled',
      { wifi: 'ssid-3', enabled: false },
      onWrite,
    );
  });

  it('unifi_delete_wifi refuses every loose confirm, then runs once on true', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(client, 'unifi_delete_wifi', { wifi: 'ssid-2' }, onWrite);
    const r = await client.callTool({
      name: 'unifi_delete_wifi',
      arguments: { wifi: 'ssid-2', confirm: true },
    });
    expect(r.isError).toBeFalsy();
    expect(onWrite).toHaveBeenCalledOnce();
  });
});
