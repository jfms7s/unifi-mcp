import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded, type Target } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, findDevice } from '../lookup.js';
import type { OfficialDevice } from '../official.js';
import { compact, modelName } from '../shape.js';
import type { Site } from '../sites.js';
import { write, type WriteDeps } from './common.js';

const deviceInput = z.string().min(1).describe('Device name, MAC, IP or id');

const deviceRow = (d: OfficialDevice) =>
  compact({ id: d.id, name: d.name, model: modelName(d.model), ip: d.ipAddress, state: d.state });

/** Lower-case colon form of a MAC in any common spelling, else undefined. */
function normaliseMac(value: string): string | undefined {
  const hex = value.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12 || !/^[0-9a-f:.-]+$/i.test(value.trim())) return undefined;
  return hex.match(/../g)!.join(':');
}

/**
 * One guarded device change. The guard reads fresh facts for each call: the
 * known clients (connected, and offline ones where they were last seen) and
 * every device's uplink from stat/device, so a port or device upstream of a
 * protected client is placed (R15). The scope itself is cached.
 */
async function change(
  deps: WriteDeps,
  args: { site?: string; device: string; confirm?: true },
  opts: {
    level: 'easy' | 'confirm';
    would: string;
    detail?: Record<string, unknown>;
    target?: (d: OfficialDevice) => Target;
    run: (site: Site, d: OfficialDevice) => Promise<object>;
  },
): Promise<unknown> {
  const site = await deps.sites.resolve(args.site);
  const devices = await deps.official.listDevices(site.id);
  const match = findDevice(devices, args.device);
  if ('none' in match) throw new Error(`No device matches "${args.device}"`);
  if ('ambiguous' in match) return ambiguous(args.device, match.ambiguous, deviceRow);
  const d = match.found;
  const [scope, clients, links] = await Promise.all([
    deps.scope(),
    opts.target ? deps.legacy.knownClients(site.ref) : [],
    opts.target ? deps.legacy.deviceLinks(site.ref) : [],
  ]);
  return guarded(
    {
      level: opts.level,
      target: opts.target?.(d),
      confirm: args.confirm,
      preview: async () =>
        compact({
          would: opts.would,
          device: d.name,
          model: modelName(d.model),
          ip: d.ipAddress,
          state: d.state,
          ...opts.detail,
        }),
      run: () => opts.run(site, d),
    },
    scope,
    clients,
    links,
  );
}

export function createDeviceWriteTools(deps: WriteDeps): ToolDefinition[] {
  const base = { site: siteInput, device: deviceInput, confirm: confirmInput };
  const deviceTarget = (d: OfficialDevice): Target => ({ kind: 'device', id: d.id });

  return [
    defineTool({
      name: 'unifi_restart_device',
      description:
        'Restart an adopted device (official RESTART). Needs confirm: true when the device is the gateway, or carries a protected network (pi-cluster by default) directly or further down its uplink chain: that restart cuts unifi-mcp off. Without confirm it previews. An ambiguous name returns the candidates.',
      inputSchema: base,
      annotations: write({ destructive: true, idempotent: false }),
      handler: (args) =>
        change(deps, args, {
          level: 'easy',
          would: 'restart',
          target: deviceTarget,
          run: async (site, d) => {
            await deps.official.deviceAction(site.id, d.id, 'RESTART');
            return { changed: 'restarting', device: d.name };
          },
        }),
    }),
    defineTool({
      name: 'unifi_power_cycle_port',
      description:
        'Power-cycle PoE on one switch port (official POWER_CYCLE). Needs confirm: true when the port is on the gateway, or feeds a protected-network client (pi-cluster by default) directly or through another switch or AP; without it the tool previews.',
      inputSchema: {
        ...base,
        port: z.number().int().min(1).describe('Port number (portIdx) on the device'),
      },
      annotations: write({ destructive: true, idempotent: false }),
      handler: ({ port, ...args }) =>
        change(deps, args, {
          level: 'easy',
          would: 'power-cycle',
          detail: { port },
          target: (d) => ({ kind: 'port', deviceId: d.id, portIdx: port }),
          run: async (site, d) => {
            await deps.official.portAction(site.id, d.id, port, 'POWER_CYCLE');
            return { changed: 'power-cycled', device: d.name, port };
          },
        }),
    }),
    defineTool({
      name: 'unifi_locate_device',
      description:
        'Turn the locate LED (blinking) of a device on or off (legacy cmd/devmgr set-locate / unset-locate).',
      inputSchema: {
        site: siteInput,
        device: deviceInput,
        on: z.boolean().describe('true starts blinking, false stops it'),
      },
      annotations: write({ destructive: false, idempotent: true }),
      handler: ({ on, ...args }) =>
        change(deps, args, {
          level: 'easy',
          would: on ? 'locate on' : 'locate off',
          run: async (site, d) => {
            const cmd = on ? 'set-locate' : 'unset-locate';
            await deps.legacy.cmd(site.ref, 'devmgr', { cmd, mac: d.macAddress.toLowerCase() });
            return { changed: on ? 'locating' : 'locate off', device: d.name };
          },
        }),
    }),
    defineTool({
      name: 'unifi_adopt_device',
      description:
        'Adopt a device waiting for adoption, by its MAC (official adopt). Adoption finishes on the console; unifi_list_devices shows it once done.',
      inputSchema: {
        site: siteInput,
        mac: z.string().min(1).describe('MAC address of the device to adopt'),
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, mac }) => {
        const macAddress = normaliseMac(mac);
        if (macAddress === undefined) throw new Error(`"${mac}" is not a MAC address`);
        const site = await deps.sites.resolve(wanted);
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'adopt', mac: macAddress }),
            run: async () => {
              await deps.official.adoptDevice(site.id, macAddress);
              return { changed: 'adoption requested', mac: macAddress };
            },
          },
          await deps.scope(),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_unadopt_device',
      description:
        'Remove (unadopt) a device from the site (official DELETE). An online device is reset to factory defaults. Always needs confirm: true; without it the tool previews, with a lock-out warning when the device is the gateway or carries a protected network.',
      inputSchema: base,
      annotations: write({ destructive: true, idempotent: true }),
      handler: (args) =>
        change(deps, args, {
          level: 'confirm',
          would: 'unadopt',
          detail: { note: 'an online device is reset to factory defaults' },
          target: deviceTarget,
          run: async (site, d) => {
            await deps.official.unadoptDevice(site.id, d.id);
            return { changed: 'unadopted', device: d.name };
          },
        }),
    }),
  ];
}
