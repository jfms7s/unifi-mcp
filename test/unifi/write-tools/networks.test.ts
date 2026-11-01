import { describe, expect, it } from 'vitest';
import { liveFixture } from '../../fixtures/live.js';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);

const DEFAULT_NET = '50edfc66-8b84-4f92-8753-9d69a080a695';
const IOT = 'f1b4fdb6-c787-4421-92bb-56d55e0ea95a';
const PI_CLUSTER = '80ec407d-e455-4a87-8b26-846881ebf07f';
const WARNING = 'This can cut unifi-mcp off from the console:';

type Out = Record<string, unknown>;
type NetworkRow = Record<string, unknown> & { id: string; metadata: unknown; default: boolean };

const listRow = (id: string) =>
  (liveFixture('official-networks') as { data: NetworkRow[] }).data.find((n) => n.id === id)!;

/**
 * What GET /networks/{id} returns: the list row plus the gateway-managed
 * fields the list leaves out (shape from the 10.6.109 spec).
 */
const detail = (id: string, octet: number) => ({
  ...listRow(id),
  cellularBackupEnabled: false,
  internetAccessEnabled: true,
  isolationEnabled: false,
  mdnsForwardingEnabled: true,
  zoneId: 'aaaaaaaa-0000-4000-8000-000000000001',
  ipv4Configuration: {
    autoScaleEnabled: false,
    hostIpAddress: `192.168.${octet}.1`,
    prefixLength: 24,
    dhcpConfiguration: {
      mode: 'SERVER',
      ipAddressRange: { start: `192.168.${octet}.6`, stop: `192.168.${octet}.254` },
      leaseTimeSeconds: 86400,
    },
  },
});

const DETAILS = {
  [`official-networks-${IOT}`]: detail(IOT, 11),
  [`official-networks-${PI_CLUSTER}`]: detail(PI_CLUSTER, 0),
  [`official-networks-${DEFAULT_NET}`]: detail(DEFAULT_NET, 10),
};
const withDetails = (opts: ConsoleOptions = {}) =>
  setup({ ...opts, fixtures: { ...DETAILS, ...opts.fixtures } });

/** The PUT body: everything GET returned except the fields the request schema has no place for. */
function putBody(id: string, octet: number) {
  const body: Partial<ReturnType<typeof detail>> = detail(id, octet);
  delete body.id;
  delete body.metadata;
  delete body.default;
  return body as Omit<ReturnType<typeof detail>, 'id' | 'metadata' | 'default'>;
}

describe('unifi_create_network', () => {
  it('is easy: posts the request as given and names the new network', async () => {
    const { call, writes } = setup({
      officialReply: { id: 'bbbbbbbb-0000-4000-8000-000000000002', name: 'guest', vlanId: 4 },
    });
    const ipv4Configuration = {
      autoScaleEnabled: false,
      hostIpAddress: '192.168.12.1',
      prefixLength: 24,
    };
    const out = await call('unifi_create_network', {
      name: 'guest',
      vlanId: 4,
      management: 'GATEWAY',
      enabled: true,
      cellularBackupEnabled: false,
      internetAccessEnabled: true,
      isolationEnabled: true,
      ipv4Configuration,
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/networks`,
        body: {
          name: 'guest',
          vlanId: 4,
          management: 'GATEWAY',
          enabled: true,
          cellularBackupEnabled: false,
          internetAccessEnabled: true,
          isolationEnabled: true,
          ipv4Configuration,
        },
      },
    ]);
    expect(out).toEqual({
      changed: 'created',
      network: { id: 'bbbbbbbb-0000-4000-8000-000000000002', name: 'guest', vlanId: 4 },
    });
  });
});

describe('unifi_update_network', () => {
  it('is confirm-level: without confirm it previews only the changed fields and sends nothing', async () => {
    const { call, writes } = withDetails();
    const out = (await call('unifi_update_network', {
      network: 'IoT',
      isolationEnabled: true,
      ipv4Configuration: { dhcpConfiguration: { leaseTimeSeconds: 3600 } },
    })) as Out;
    expect(writes).toEqual([]);
    expect(out).toEqual({
      preview: {
        would: 'update network',
        network: 'IoT',
        changes: {
          isolationEnabled: { before: false, after: true },
          'ipv4Configuration.dhcpConfiguration.leaseTimeSeconds': { before: 86400, after: 3600 },
        },
      },
      requires: 'confirm: true',
    });
  });

  it('with confirm PUTs the whole merged object, minus id, metadata and default', async () => {
    const { call, writes } = withDetails();
    const out = await call('unifi_update_network', {
      network: IOT,
      isolationEnabled: true,
      ipv4Configuration: { dhcpConfiguration: { leaseTimeSeconds: 3600 } },
      confirm: true,
    });
    const expected = putBody(IOT, 11);
    expected.isolationEnabled = true;
    expected.ipv4Configuration.dhcpConfiguration.leaseTimeSeconds = 3600;
    expect(writes).toEqual([
      { method: 'PUT', path: `${OFFICIAL_SITE}/networks/${IOT}`, body: expected },
    ]);
    // The DHCP range and everything else not named survive the merge.
    expect(writes[0]!.body).toMatchObject({
      ipv4Configuration: { dhcpConfiguration: { ipAddressRange: { start: '192.168.11.6' } } },
      vlanId: 2,
      name: 'IoT',
    });
    expect(out).toEqual({
      changed: 'updated',
      network: 'IoT',
      fields: ['isolationEnabled', 'ipv4Configuration.dhcpConfiguration.leaseTimeSeconds'],
    });
  });

  it('a nested object whose discriminator changes is replaced, not merged', async () => {
    const { call, writes } = withDetails();
    await call('unifi_update_network', {
      network: 'IoT',
      ipv4Configuration: {
        dhcpConfiguration: { mode: 'RELAY', dhcpServerIpAddresses: ['192.168.10.5'] },
      },
      confirm: true,
    });
    const body = writes[0]!.body as {
      ipv4Configuration: { dhcpConfiguration: unknown; hostIpAddress: string };
    };
    expect(body.ipv4Configuration.dhcpConfiguration).toEqual({
      mode: 'RELAY',
      dhcpServerIpAddresses: ['192.168.10.5'],
    });
    expect(body.ipv4Configuration.hostIpAddress).toBe('192.168.11.1');
  });

  it('a change that changes nothing sends nothing, confirmed or not', async () => {
    const { call, writes } = withDetails();
    expect(
      await call('unifi_update_network', {
        network: 'IoT',
        isolationEnabled: false,
        confirm: true,
      }),
    ).toEqual({ unchanged: true, network: 'IoT' });
    expect(writes).toEqual([]);
  });

  it('pi-cluster: the preview carries the lock-out warning, and the confirmed change repeats it', async () => {
    const { call, writes } = withDetails();
    const preview = (await call('unifi_update_network', {
      network: 'pi-cluster',
      enabled: false,
    })) as Out;
    expect(writes).toEqual([]);
    expect(preview.warning).toBe(`${WARNING} it changes pi-cluster, a protected network`);
    expect(preview.preview).toMatchObject({ changes: { enabled: { before: true, after: false } } });

    const done = (await call('unifi_update_network', {
      network: 'pi-cluster',
      enabled: false,
      confirm: true,
    })) as Out;
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({
      method: 'PUT',
      path: `${OFFICIAL_SITE}/networks/${PI_CLUSTER}`,
    });
    expect(done.warning).toBe(`${WARNING} it changes pi-cluster, a protected network`);
  });

  it('an unknown network fails before anything is sent', async () => {
    const { call, writes } = withDetails();
    await expect(call('unifi_update_network', { network: 'nope', enabled: false })).rejects.toThrow(
      /No network matches "nope"/,
    );
    expect(writes).toEqual([]);
  });
});

describe('unifi_delete_network', () => {
  it('is confirm-level even for an unprotected network: no confirm, nothing sent', async () => {
    const { call, writes } = withDetails();
    const out = (await call('unifi_delete_network', { network: 'IoT' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBeUndefined();
    expect(out).toMatchObject({
      preview: { would: 'delete network', network: 'IoT', vlanId: 2 },
      requires: 'confirm: true',
    });
  });

  it('with confirm sends DELETE for that network only', async () => {
    const { call, writes } = withDetails();
    expect(await call('unifi_delete_network', { network: 'IoT', confirm: true })).toEqual({
      changed: 'deleted',
      network: 'IoT',
    });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${OFFICIAL_SITE}/networks/${IOT}`, body: undefined },
    ]);
  });

  it('pi-cluster: the preview warns of the lock-out', async () => {
    const { call, writes } = withDetails();
    const out = (await call('unifi_delete_network', { network: PI_CLUSTER })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBe(`${WARNING} it changes pi-cluster, a protected network`);
  });
});

describe('confirm-level network tools through the MCP SDK', () => {
  it('unifi_update_network refuses every loose confirm', async () => {
    const { tools, onWrite } = withDetails();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_update_network',
      { network: 'IoT', isolationEnabled: true },
      onWrite,
    );
  });

  it('unifi_update_network on pi-cluster refuses every loose confirm, then runs once on true', async () => {
    const { tools, onWrite } = withDetails();
    const client = await connect(tools);
    const args = { network: 'pi-cluster', enabled: false };
    await expectRejectsLooseConfirm(client, 'unifi_update_network', args, onWrite);
    const r = await client.callTool({
      name: 'unifi_update_network',
      arguments: { ...args, confirm: true },
    });
    expect(r.isError).toBeFalsy();
    expect(JSON.stringify(r.content)).toContain(WARNING);
    expect(onWrite).toHaveBeenCalledOnce();
  });

  it('unifi_delete_network refuses every loose confirm', async () => {
    const { tools, onWrite } = withDetails();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(client, 'unifi_delete_network', { network: 'IoT' }, onWrite);
    await expectRejectsLooseConfirm(
      client,
      'unifi_delete_network',
      { network: 'pi-cluster' },
      onWrite,
    );
  });
});
