import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createServer } from '../../src/mcp/server.js';
import { defineTool } from '../../src/mcp/types.js';
import {
  guarded,
  loadProtectedScope,
  touchesProtected,
  type ProtectedScope,
  type Target,
} from '../../src/unifi/guard.js';
import { confirmInput } from '../../src/unifi/inputs.js';
import type { KnownClient } from '../../src/unifi/legacy.js';
import { readDeps } from './fixtures.js';

const PI_CLUSTER = '80ec407d-e455-4a87-8b26-846881ebf07f';
const PI_CLUSTER_LEGACY = '6ae51197aa840627805aa50a';
const DEFAULT_NET = '50edfc66-8b84-4f92-8753-9d69a080a695';
const IOT = 'f1b4fdb6-c787-4421-92bb-56d55e0ea95a';
const GATEWAY = '0b8af13c-8fc3-3809-96d4-cd4e6e1720c8';
/** USW Ultra 60W: port 7 feeds most k3s nodes, port 3 feeds data-archive on Default. */
const SWITCH_PI = '3bd4c282-e99a-31b8-88bb-4a86e3f36403';
/** USW Flex: only Default clients. */
const SWITCH_DEFAULT = '15e622d8-6668-3466-8e66-20734abe3e10';
const WARNING = 'This can cut unifi-mcp off from the console:';

let scope: ProtectedScope;
let clients: KnownClient[];

beforeAll(async () => {
  const deps = readDeps();
  const site = await deps.sites.resolve();
  scope = await loadProtectedScope(['pi-cluster'], deps, site);
  clients = await deps.legacy.knownClients(site.ref);
});

const touches = (target: Target) => touchesProtected(target, scope, clients);
const clientNamed = (name: string) => clients.find((c) => c.name === name)!;

describe('loadProtectedScope', () => {
  it('resolves pi-cluster to both its ids, its subnet, the gateway and the switch that carries it', () => {
    expect([...scope.networkIds].sort()).toEqual([PI_CLUSTER_LEGACY, PI_CLUSTER].sort());
    expect(scope.subnets).toEqual([{ cidr: '192.168.0.0/24', network: 'pi-cluster' }]);
    expect(scope.gatewayDeviceIds.has(GATEWAY)).toBe(true);
    expect(scope.uplinkDeviceIds.has(SWITCH_PI)).toBe(true);
    expect(scope.uplinkDeviceIds.has(SWITCH_DEFAULT)).toBe(false);
  });

  it('matches names case-insensitively and accepts ids', async () => {
    const deps = readDeps();
    const site = await deps.sites.resolve();
    for (const name of ['PI-Cluster', PI_CLUSTER, PI_CLUSTER_LEGACY]) {
      const s = await loadProtectedScope([name], deps, site);
      expect(s.subnets).toEqual([{ cidr: '192.168.0.0/24', network: 'pi-cluster' }]);
    }
  });

  it('an unknown name fails at first use and names the networks that exist', async () => {
    const deps = readDeps();
    const site = await deps.sites.resolve();
    await expect(loadProtectedScope(['k3s'], deps, site)).rejects.toThrow(
      /"k3s".*Default, IoT, pi-cluster/,
    );
  });

  it('no names protects nothing but the gateway', async () => {
    const deps = readDeps();
    const site = await deps.sites.resolve();
    const empty = await loadProtectedScope([], deps, site);
    expect(empty.networkIds.size).toBe(0);
    expect(touchesProtected({ kind: 'ip', ip: '192.168.0.17' }, empty, clients)).toBeUndefined();
    expect(touchesProtected({ kind: 'device', id: GATEWAY }, empty, clients)).toMatch(/gateway/);
  });
});

describe('touchesProtected: the Review Focus 2 matrix', () => {
  it.each<[string, Target, RegExp | undefined]>([
    ['pi-cluster by official id', { kind: 'network', id: PI_CLUSTER }, /pi-cluster/],
    ['pi-cluster by legacy id', { kind: 'network', id: PI_CLUSTER_LEGACY }, /pi-cluster/],
    ['Default network', { kind: 'network', id: DEFAULT_NET }, undefined],
    ['IP inside 192.168.0.0/24', { kind: 'ip', ip: '192.168.0.17' }, /192\.168\.0\.17.*pi-cluster/],
    ['IP on IoT', { kind: 'ip', ip: '192.168.11.5' }, undefined],
    ['IP of the gateway on pi-cluster', { kind: 'ip', ip: '192.168.0.1' }, /pi-cluster/],
    ['gateway device by id', { kind: 'device', id: GATEWAY }, /gateway/],
    ['gateway device by MAC', { kind: 'device', id: '02-00-00-00-00-01' }, /gateway/],
    ['switch carrying k3s nodes', { kind: 'device', id: SWITCH_PI }, /pi-cluster/],
    ['switch with only Default clients', { kind: 'device', id: SWITCH_DEFAULT }, undefined],
    [
      'switch port feeding k3s nodes',
      { kind: 'port', deviceId: SWITCH_PI, portIdx: 7 },
      /port 7.*pi-cluster/,
    ],
    [
      'same switch, port feeding data-archive',
      { kind: 'port', deviceId: SWITCH_PI, portIdx: 3 },
      undefined,
    ],
    [
      'same switch, port with no known client (could be its uplink)',
      { kind: 'port', deviceId: SWITCH_PI, portIdx: 8 },
      /uplink/,
    ],
    ['other switch port', { kind: 'port', deviceId: SWITCH_DEFAULT, portIdx: 2 }, undefined],
    ['any gateway port', { kind: 'port', deviceId: GATEWAY, portIdx: 4 }, /gateway/],
    [
      'policy into pi-cluster',
      { kind: 'policy', sourceNetworkIds: [IOT], destNetworkIds: [DEFAULT_NET, PI_CLUSTER] },
      /pi-cluster/,
    ],
    [
      'policy out of pi-cluster',
      { kind: 'policy', sourceNetworkIds: [PI_CLUSTER_LEGACY], destNetworkIds: [] },
      /pi-cluster/,
    ],
    [
      'policy IoT → Default',
      { kind: 'policy', sourceNetworkIds: [IOT], destNetworkIds: [DEFAULT_NET] },
      undefined,
    ],
  ])('%s', (_, target, expected) => {
    const reason = touches(target);
    if (expected === undefined) expect(reason).toBeUndefined();
    else expect(reason).toMatch(expected);
  });

  it('a k3s node found by name (client-22, 192.168.0.231) by IP and by MAC', () => {
    const node = clientNamed('client-22');
    expect(node.ip).toBe('192.168.0.231');
    expect(touches({ kind: 'client', ipOrMac: node.ip! })).toMatch(/client-22.*pi-cluster/);
    expect(touches({ kind: 'client', ipOrMac: node.mac.toUpperCase() })).toMatch(/pi-cluster/);
  });

  it('a client on Default is not protected', () => {
    const nas = clients.find((c) => c.ip === '192.168.10.3')!;
    expect(touches({ kind: 'client', ipOrMac: nas.mac })).toBeUndefined();
  });

  it('an unknown client given by an IP inside the subnet is still protected', () => {
    expect(touches({ kind: 'client', ipOrMac: '192.168.0.99' })).toMatch(/pi-cluster/);
  });

  it('a client whose network is pi-cluster but whose IP is unknown is protected by network id', () => {
    const lone: KnownClient = {
      id: 'x',
      mac: '02:00:00:00:99:99',
      name: 'lone',
      blocked: false,
      networkId: PI_CLUSTER_LEGACY,
    };
    expect(touchesProtected({ kind: 'client', ipOrMac: lone.mac }, scope, [lone])).toMatch(
      /pi-cluster/,
    );
  });

  it('a network target given by name, in any case', () => {
    expect(touches({ kind: 'network', id: 'PI-Cluster' })).toMatch(/pi-cluster/);
    expect(touches({ kind: 'network', id: 'iot' })).toBeUndefined();
  });
});

describe('touchesProtected leans to confirm on targets it cannot place', () => {
  it.each<[string, Target]>([
    ['a client MAC the console does not know', { kind: 'client', ipOrMac: '02:00:00:ff:ff:ff' }],
    ['a client given by name', { kind: 'client', ipOrMac: 'client-22' }],
    ['a client given by IPv6', { kind: 'client', ipOrMac: 'fd00::17' }],
    ['a malformed client value', { kind: 'client', ipOrMac: '192.168.0' }],
    ['a device id unifi-mcp does not know', { kind: 'device', id: 'no-such-device' }],
    ['a device MAC unifi-mcp does not know', { kind: 'device', id: '02:00:00:00:ff:01' }],
    ['a port on an unknown device', { kind: 'port', deviceId: 'no-such-device', portIdx: 1 }],
  ])('%s', (_, target) => {
    expect(touches(target)).toMatch(/can't place .* so it may be on a protected network/);
  });

  it('a known client with neither network nor IP', () => {
    const ghost: KnownClient = { id: 'g', mac: '02:00:00:00:99:98', name: 'ghost', blocked: false };
    expect(touchesProtected({ kind: 'client', ipOrMac: ghost.mac }, scope, [ghost])).toMatch(
      /can't place/,
    );
  });

  it('an unknown IPv4 client outside every protected subnet is placed, so stays easy', () => {
    expect(touches({ kind: 'client', ipOrMac: '192.168.11.200' })).toBeUndefined();
  });
});

describe('loadProtectedScope refuses a protected network it cannot place', () => {
  it.each([
    ['no ip_subnet', (n: Record<string, unknown>) => void delete n.ip_subnet],
    ['an unparseable ip_subnet', (n: Record<string, unknown>) => void (n.ip_subnet = 'fd00::/64')],
  ])('%s', async (_, mutate) => {
    const deps = readDeps();
    const site = await deps.sites.resolve();
    const nets = await deps.legacy.networkConf(site.ref);
    const broken = nets.map((n) => {
      if (n.name !== 'pi-cluster') return n;
      const copy = { ...n } as Record<string, unknown>;
      mutate(copy);
      return copy as typeof n;
    });
    const legacy = { ...deps.legacy, networkConf: async () => broken };
    await expect(loadProtectedScope(['pi-cluster'], { ...deps, legacy }, site)).rejects.toThrow(
      /pi-cluster.*subnet/,
    );
  });

  it('a protected network with no legacy row at all', async () => {
    const deps = readDeps();
    const site = await deps.sites.resolve();
    const nets = (await deps.legacy.networkConf(site.ref)).filter((n) => n.name !== 'pi-cluster');
    const legacy = { ...deps.legacy, networkConf: async () => nets };
    await expect(loadProtectedScope(['pi-cluster'], { ...deps, legacy }, site)).rejects.toThrow(
      /pi-cluster.*subnet/,
    );
  });
});

describe('guarded', () => {
  const protectedTarget: Target = { kind: 'ip', ip: '192.168.0.17' };
  const plainTarget: Target = { kind: 'ip', ip: '192.168.11.5' };

  function spies() {
    const preview = vi.fn(async () => ({ would: 'block 192.168.0.17' }));
    const run = vi.fn(async () => ({ done: true }));
    return { preview, run };
  }

  it('easy on an unprotected target runs without confirm and without a preview', async () => {
    const { preview, run } = spies();
    const out = await guarded({ level: 'easy', target: plainTarget, preview, run }, scope, clients);
    expect(out).toEqual({ done: true });
    expect(run).toHaveBeenCalledTimes(1);
    expect(preview).not.toHaveBeenCalled();
  });

  it('easy on a protected target without confirm returns the preview and never calls run', async () => {
    const { preview, run } = spies();
    const out = await guarded(
      { level: 'easy', target: protectedTarget, preview, run },
      scope,
      clients,
    );
    expect(run).not.toHaveBeenCalled();
    expect(out).toEqual({
      warning: expect.stringMatching(/^This can cut unifi-mcp off from the console: .*pi-cluster/),
      preview: { would: 'block 192.168.0.17' },
      requires: 'confirm: true',
    });
    // The warning is what the preview opens with.
    expect(Object.keys(out as object)[0]).toBe('warning');
  });

  it('easy on a protected target with confirm: true runs once and repeats the warning', async () => {
    const { preview, run } = spies();
    const out = await guarded(
      { level: 'easy', target: protectedTarget, confirm: true, preview, run },
      scope,
      clients,
    );
    expect(run).toHaveBeenCalledTimes(1);
    expect(out).toEqual({ done: true, warning: expect.stringContaining(WARNING) });
  });

  it('confirm level without confirm previews, with no warning when nothing protected is touched', async () => {
    const { preview, run } = spies();
    const out = await guarded(
      { level: 'confirm', target: plainTarget, preview, run },
      scope,
      clients,
    );
    expect(run).not.toHaveBeenCalled();
    expect(out).toEqual({ preview: { would: 'block 192.168.0.17' }, requires: 'confirm: true' });
  });

  it('confirm level with confirm runs once, no warning', async () => {
    const { preview, run } = spies();
    const out = await guarded({ level: 'confirm', confirm: true, preview, run }, scope, clients);
    expect(run).toHaveBeenCalledTimes(1);
    expect(out).toEqual({ done: true });
  });

  it('anything but the literal true is not a confirm', async () => {
    for (const confirm of ['true', 1, {}, [true], false]) {
      const { preview, run } = spies();
      await guarded(
        { level: 'confirm', target: protectedTarget, confirm: confirm as never, preview, run },
        scope,
        clients,
      );
      expect(run, JSON.stringify(confirm)).not.toHaveBeenCalled();
    }
  });

  it('a result that already has a warning is wrapped, not overwritten', async () => {
    const out = await guarded(
      {
        level: 'easy',
        target: protectedTarget,
        confirm: true,
        preview: async () => ({}),
        run: async () => ({ warning: 'console said so' }),
      },
      scope,
      clients,
    );
    expect(out).toEqual({
      result: { warning: 'console said so' },
      warning: expect.stringContaining(WARNING),
    });
  });

  it('a non-object result is wrapped so the warning still shows', async () => {
    const out = await guarded(
      {
        level: 'easy',
        target: protectedTarget,
        confirm: true,
        preview: async () => ({}),
        run: async () => undefined,
      },
      scope,
      clients,
    );
    expect(out).toEqual({ result: undefined, warning: expect.stringContaining(WARNING) });
  });

  it('a preview that fails never falls through to run', async () => {
    const run = vi.fn(async () => ({}));
    await expect(
      guarded(
        {
          level: 'easy',
          target: protectedTarget,
          preview: async () => Promise.reject(new Error('nope')),
          run,
        },
        scope,
        clients,
      ),
    ).rejects.toThrow('nope');
    expect(run).not.toHaveBeenCalled();
  });
});

describe('guarded through the MCP SDK argument parsing', () => {
  async function connect(run: () => Promise<object>) {
    const tool = defineTool({
      name: 'unifi_test_block_ip',
      description: 'test',
      inputSchema: { ip: z.string(), confirm: confirmInput },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
      handler: ({ ip, confirm }) =>
        guarded(
          {
            level: 'easy',
            target: { kind: 'ip', ip },
            confirm,
            preview: async () => ({ block: ip }),
            run,
          },
          scope,
          clients,
        ),
    });
    const server = createServer([tool]);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 't', version: '0' });
    await Promise.all([client.connect(ct), server.connect(st)]);
    return client;
  }
  const text = (r: unknown) => (r as { content: Array<{ text: string }> }).content[0]!.text;

  it('no confirm: preview with the warning; confirm as a string or number is rejected; true runs', async () => {
    const run = vi.fn(async () => ({ blocked: true }));
    const client = await connect(run);
    const args = { ip: '192.168.0.17' };

    const preview = await client.callTool({ name: 'unifi_test_block_ip', arguments: args });
    expect(preview.isError).toBeFalsy();
    expect(text(preview)).toContain(WARNING);
    expect(run).not.toHaveBeenCalled();

    for (const confirm of ['true', 1, 'yes']) {
      const r = await client.callTool({
        name: 'unifi_test_block_ip',
        arguments: { ...args, confirm },
      });
      expect(r.isError, JSON.stringify(confirm)).toBe(true);
    }
    expect(run).not.toHaveBeenCalled();

    const done = await client.callTool({
      name: 'unifi_test_block_ip',
      arguments: { ...args, confirm: true },
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(JSON.parse(text(done))).toEqual({
      blocked: true,
      warning: expect.stringContaining(WARNING),
    });
  });
});
