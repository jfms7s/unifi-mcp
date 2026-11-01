import { describe, expect, it } from 'vitest';
import { WRITE_TOOL_NAMES } from '../../../src/unifi/write-tools/index.js';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { DAISY_CHAIN, FLEX_MAC } from '../topology.js';
import {
  LEGACY_SITE,
  OFFICIAL_SITE,
  fakeWriteConsole,
  withOfflineUser,
  type ConsoleOptions,
} from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);

const GATEWAY = '0b8af13c-8fc3-3809-96d4-cd4e6e1720c8';
/** device-2, USW Ultra 60W: carries the k3s nodes. */
const PI_SWITCH = '3bd4c282-e99a-31b8-88bb-4a86e3f36403';
/** device-4, USW Flex: Default clients only. */
const FLEX = '15e622d8-6668-3466-8e66-20734abe3e10';
const WARNING = 'This can cut unifi-mcp off from the console:';

type Out = Record<string, unknown>;

/** A k3s node that is offline, last seen on the Flex's port 6. */
const offlineNode = withOfflineUser({
  _id: 'offline-k3s',
  mac: '02:00:00:00:99:10',
  hostname: 'k3s-node-9',
  is_wired: true,
  last_ip: '192.168.0.209',
  last_connection_network_id: '6ae51197aa840627805aa50a',
  last_uplink_mac: FLEX_MAC,
  last_uplink_remote_port: 6,
});

describe('createWriteTools', () => {
  it('registers exactly the client, device and port tools, all with WRITE annotations', () => {
    const { tools } = setup();
    expect(tools.map((t) => t.name).sort()).toEqual([...WRITE_TOOL_NAMES].sort());
    const destructive = new Set([
      'unifi_block_client',
      'unifi_restart_device',
      'unifi_power_cycle_port',
      'unifi_unadopt_device',
    ]);
    for (const t of tools) {
      expect(t.annotations, t.name).toMatchObject({
        readOnlyHint: false,
        openWorldHint: false,
        destructiveHint: destructive.has(t.name),
      });
      expect(typeof t.annotations.idempotentHint, t.name).toBe('boolean');
    }
  });
});

describe('unifi_restart_device', () => {
  it('posts RESTART to the official device action and names the device', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_restart_device', { device: 'device-4' })).toEqual({
      changed: 'restarting',
      device: 'device-4',
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/devices/${FLEX}/actions`,
        body: { action: 'RESTART' },
      },
    ]);
  });

  it('the gateway is confirm-level: a preview with the lock-out warning, nothing sent', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_restart_device', { device: 'Gateway CGU' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toBe(
      `${WARNING} Gateway CGU is the gateway, unifi-mcp's way into the console`,
    );
    expect(out.preview).toMatchObject({ would: 'restart', device: 'Gateway CGU' });
    expect(out.requires).toBe('confirm: true');
  });

  it('the gateway with confirm: true restarts it and repeats the warning', async () => {
    const { call, writes } = setup();
    const out = await call('unifi_restart_device', { device: GATEWAY, confirm: true });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/devices/${GATEWAY}/actions`,
        body: { action: 'RESTART' },
      },
    ]);
    expect(out).toEqual({
      changed: 'restarting',
      device: 'Gateway CGU',
      warning: expect.stringContaining(WARNING),
    });
  });

  it('the switch that carries the k3s nodes is guarded', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_restart_device', { device: PI_SWITCH })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/device-2 carries .* on pi-cluster/);
  });

  it('R15 daisy chain: the Flex feeding the k3s switch is guarded', async () => {
    const { call, writes } = setup({ links: DAISY_CHAIN });
    const out = (await call('unifi_restart_device', { device: 'device-4' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/device-4 feeds device-2, which carries .* on pi-cluster/);
  });

  it('R15 offline node: the Flex carrying an offline k3s node is guarded', async () => {
    const { call, writes } = setup({ fixtures: { 'legacy-rest-user': offlineNode } });
    const out = (await call('unifi_restart_device', { device: 'device-4' })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/device-4 carries k3s-node-9 \(192\.168\.0\.209\) on pi-cluster/);
  });

  it('an ambiguous name returns the candidates and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_restart_device', { device: 'device' })) as Out;
    expect(out).toMatchObject({ ambiguous: true });
    expect(out.candidates).toHaveLength(3);
    expect(writes).toEqual([]);
  });

  it('no match is an error and sends nothing', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_restart_device', { device: 'toaster' })).rejects.toThrow(
      'No device matches "toaster"',
    );
    expect(writes).toEqual([]);
  });
});

describe('unifi_power_cycle_port', () => {
  const portPath = (id: string, port: number) =>
    `${OFFICIAL_SITE}/devices/${id}/interfaces/ports/${port}/actions`;

  it('posts POWER_CYCLE to the port action and names device and port', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_power_cycle_port', { device: 'device-4', port: 2 })).toEqual({
      changed: 'power-cycled',
      device: 'device-4',
      port: 2,
    });
    expect(writes).toEqual([
      { method: 'POST', path: portPath(FLEX, 2), body: { action: 'POWER_CYCLE' } },
    ]);
  });

  it('a port feeding k3s nodes previews and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_power_cycle_port', { device: 'device-2', port: 7 })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/^This can cut .*port 7 on device-2 feeds .* on pi-cluster/);
    expect(out.preview).toMatchObject({ would: 'power-cycle', device: 'device-2', port: 7 });
  });

  it('any gateway port previews', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_power_cycle_port', { device: GATEWAY, port: 2 })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/a port on the gateway/);
  });

  it('R15 daisy chain: the Flex port feeding the k3s switch previews; as wired today it is easy', async () => {
    const chained = setup({ links: DAISY_CHAIN });
    const out = (await chained.call('unifi_power_cycle_port', {
      device: 'device-4',
      port: 5,
    })) as Out;
    expect(chained.writes).toEqual([]);
    expect(out.warning).toMatch(
      /port 5 on device-4 feeds device-2, which carries .* on pi-cluster/,
    );

    const today = setup();
    await today.call('unifi_power_cycle_port', { device: 'device-4', port: 5 });
    expect(today.writes).toEqual([
      { method: 'POST', path: portPath(FLEX, 5), body: { action: 'POWER_CYCLE' } },
    ]);
  });

  it('R15 offline node: its last port previews', async () => {
    const { call, writes } = setup({ fixtures: { 'legacy-rest-user': offlineNode } });
    const out = (await call('unifi_power_cycle_port', { device: 'device-4', port: 6 })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/port 6 on device-4 feeds k3s-node-9/);
  });

  it('a port number below 1 is refused before anything is sent', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_power_cycle_port', { device: 'device-4', port: 0 })).rejects.toThrow();
    expect(writes).toEqual([]);
  });
});

describe('unifi_locate_device', () => {
  it.each([
    [true, 'set-locate', 'locating'],
    [false, 'unset-locate', 'locate off'],
  ])('on: %s posts %s to cmd/devmgr with the device MAC', async (on, cmd, changed) => {
    const { call, writes } = setup();
    expect(await call('unifi_locate_device', { device: 'device-3', on })).toEqual({
      changed,
      device: 'device-3',
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${LEGACY_SITE}/cmd/devmgr`,
        body: { cmd, mac: '02:00:00:00:00:03' },
      },
    ]);
  });

  it('on is required', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_locate_device', { device: 'device-3' })).rejects.toThrow();
    expect(writes).toEqual([]);
  });
});

describe('unifi_adopt_device', () => {
  it('posts the MAC to the official devices collection', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_adopt_device', { mac: '02-00-00-00-00-99' })).toEqual({
      changed: 'adoption requested',
      mac: '02:00:00:00:00:99',
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: `${OFFICIAL_SITE}/devices`,
        body: { macAddress: '02:00:00:00:00:99', ignoreDeviceLimit: false },
      },
    ]);
  });

  it('a value that is not a MAC is refused, nothing sent', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_adopt_device', { mac: 'device-9' })).rejects.toThrow(/not a MAC/);
    expect(writes).toEqual([]);
  });
});

describe('unifi_unadopt_device', () => {
  it('without confirm previews, factory reset included, and sends nothing', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_unadopt_device', { device: 'device-4' })) as Out;
    expect(writes).toEqual([]);
    expect(out).not.toHaveProperty('warning');
    expect(out.preview).toMatchObject({ would: 'unadopt', device: 'device-4' });
    expect(JSON.stringify(out.preview)).toMatch(/factory defaults/);
    expect(out.requires).toBe('confirm: true');
  });

  it('with confirm: true sends DELETE for the device', async () => {
    const { call, writes } = setup();
    expect(await call('unifi_unadopt_device', { device: 'device-4', confirm: true })).toEqual({
      changed: 'unadopted',
      device: 'device-4',
    });
    expect(writes).toEqual([
      { method: 'DELETE', path: `${OFFICIAL_SITE}/devices/${FLEX}`, body: undefined },
    ]);
  });

  it('the gateway preview carries the lock-out warning', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_unadopt_device', { device: GATEWAY })) as Out;
    expect(writes).toEqual([]);
    expect(out.warning).toMatch(/Gateway CGU is the gateway/);
  });
});

describe('confirm-level device tools through the MCP SDK', () => {
  it('unifi_unadopt_device refuses every loose confirm, then runs once on true', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_unadopt_device',
      { device: 'device-4' },
      onWrite,
    );
    const r = await client.callTool({
      name: 'unifi_unadopt_device',
      arguments: { device: 'device-4', confirm: true },
    });
    expect(r.isError).toBeFalsy();
    expect(onWrite).toHaveBeenCalledOnce();
  });

  it('unifi_restart_device on the gateway refuses every loose confirm, then runs once on true', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(client, 'unifi_restart_device', { device: GATEWAY }, onWrite);
    const preview = await client.callTool({
      name: 'unifi_restart_device',
      arguments: { device: GATEWAY },
    });
    expect(JSON.stringify(preview.content)).toContain(WARNING);
    const r = await client.callTool({
      name: 'unifi_restart_device',
      arguments: { device: GATEWAY, confirm: true },
    });
    expect(r.isError).toBeFalsy();
    expect(onWrite).toHaveBeenCalledOnce();
  });

  it('unifi_power_cycle_port on a k3s port refuses every loose confirm', async () => {
    const { tools, onWrite } = setup();
    const client = await connect(tools);
    await expectRejectsLooseConfirm(
      client,
      'unifi_power_cycle_port',
      { device: PI_SWITCH, port: 7 },
      onWrite,
    );
  });
});
