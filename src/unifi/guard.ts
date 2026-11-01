import type { KnownClient } from './legacy.js';
import type { ReadDeps } from './read-common.js';
import { isGatewayModel } from './shape.js';
import type { Site } from './sites.js';

/**
 * What unifi-mcp must not cut itself off from: the protected networks (by
 * their official and legacy ids and their subnets), the gateway, and the
 * devices that carry a protected network's clients. Device sets hold both the
 * official id and the MAC, so a target given either way matches.
 */
export interface ProtectedScope {
  networkIds: Set<string>;
  subnets: Array<{ cidr: string; network: string }>;
  gatewayDeviceIds: Set<string>;
  uplinkDeviceIds: Set<string>;
  /** Official device id → MAC and name, to match a port target to the clients behind it. */
  devices: Map<string, { mac: string; name: string }>;
  /** Protected network id (official and legacy) → name, for the reason text. */
  networkNames: Map<string, string>;
}

export type Target =
  | { kind: 'network'; id: string }
  | { kind: 'client'; ipOrMac: string }
  | { kind: 'ip'; ip: string }
  | { kind: 'device'; id: string }
  | { kind: 'port'; deviceId: string; portIdx: number }
  | { kind: 'policy'; sourceNetworkIds: string[]; destNetworkIds: string[] };

export type Guard = 'easy' | 'confirm';

export interface GuardPreview {
  warning?: string;
  preview: object;
  requires: 'confirm: true';
}

export const CUT_OFF_WARNING = 'This can cut unifi-mcp off from the console:';

const GATEWAY_TYPES = new Set(['udm', 'ugw', 'uxg']);

// ---- addresses -------------------------------------------------------------

function ipv4(value: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value.trim());
  if (!m) return undefined;
  const octets = m.slice(1).map(Number);
  if (octets.some((o) => o > 255)) return undefined;
  return octets.reduce((n, o) => n * 256 + o, 0);
}

const dotted = (n: number) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');

/** `192.168.0.1/24` (the gateway's address, as rest/networkconf stores it) → `192.168.0.0/24`. */
function networkCidr(subnet: string): string | undefined {
  const [addr, bits] = subnet.split('/');
  const ip = addr === undefined ? undefined : ipv4(addr);
  const prefix = Number(bits);
  if (ip === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return undefined;
  const size = 2 ** (32 - prefix);
  return `${dotted(ip - (ip % size))}/${prefix}`;
}

function inCidr(ip: number, cidr: string): boolean {
  const [addr, bits] = cidr.split('/');
  const base = ipv4(addr ?? '');
  if (base === undefined) return false;
  const size = 2 ** (32 - Number(bits));
  return ip >= base && ip < base + size;
}

/** Lower-case colon form when the value is a MAC in any common spelling, else undefined. */
function mac(value: string): string | undefined {
  const hex = value.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12 || !/^[0-9a-f:.-]+$/i.test(value)) return undefined;
  return hex.match(/../g)!.join(':');
}

const sameMac = (a: string | undefined, b: string | undefined) =>
  a !== undefined && b !== undefined && mac(a) !== undefined && mac(a) === mac(b);

// ---- scope -----------------------------------------------------------------

/**
 * Resolves the configured protected network names or ids (names ignore case)
 * against the console. An unknown name fails here, at first use, and lists
 * the networks that exist, so a typo never leaves the cluster unprotected.
 */
export async function loadProtectedScope(
  names: string[],
  deps: Pick<ReadDeps, 'official' | 'legacy'>,
  site: Site,
): Promise<ProtectedScope> {
  const [officialNets, legacyNets, devices, basics, stations] = await Promise.all([
    deps.official.listNetworks(site.id),
    deps.legacy.networkConf(site.ref),
    deps.official.listDevices(site.id),
    deps.legacy.devicesBasic(site.ref),
    deps.legacy.stations(site.ref),
  ]);

  const lower = (s: string) => s.toLowerCase();
  const scope: ProtectedScope = {
    networkIds: new Set(),
    subnets: [],
    gatewayDeviceIds: new Set(),
    uplinkDeviceIds: new Set(),
    devices: new Map(),
    networkNames: new Map(),
  };

  for (const wanted of names) {
    const o = officialNets.find((n) => n.id === wanted || lower(n.name) === lower(wanted));
    const l = legacyNets.find(
      (n) =>
        n._id === wanted ||
        lower(n.name) === lower(wanted) ||
        (o && lower(n.name) === lower(o.name)),
    );
    if (!o && !l) {
      const existing = [
        ...new Set([...officialNets.map((n) => n.name), ...legacyNets.map((n) => n.name)]),
      ];
      throw new Error(
        `Protected network "${wanted}" (UNIFI_MCP_PROTECTED_NETWORKS) is not on this console; its networks are: ${existing.join(', ')}`,
      );
    }
    const name = o?.name ?? l!.name;
    for (const id of [o?.id, l?._id]) {
      if (id === undefined) continue;
      scope.networkIds.add(id);
      scope.networkNames.set(id, name);
    }
    const cidr = l?.ip_subnet === undefined ? undefined : networkCidr(l.ip_subnet);
    // Without its subnet, an address on the network can't be placed and would read as easy.
    if (cidr === undefined) {
      throw new Error(
        `Protected network "${name}" has no IPv4 subnet unifi-mcp can read (rest/networkconf ip_subnet${l?.ip_subnet ? ` is "${l.ip_subnet}"` : ' is missing'}), so addresses on it can't be placed; refusing to guard changes blind`,
      );
    }
    if (!scope.subnets.some((s) => s.cidr === cidr)) scope.subnets.push({ cidr, network: name });
  }

  const gatewayMacs = new Set(
    basics.filter((b) => GATEWAY_TYPES.has(b.type)).map((b) => mac(b.mac)),
  );
  const carrying = new Set<string>();
  for (const s of stations) {
    const ip = s.ip === undefined ? undefined : ipv4(s.ip);
    const onProtected =
      (s.network_id !== undefined && scope.networkIds.has(s.network_id)) ||
      (ip !== undefined && scope.subnets.some((n) => inCidr(ip, n.cidr)));
    const uplink = mac(s.sw_mac ?? s.ap_mac ?? '');
    if (onProtected && uplink) carrying.add(uplink);
  }
  for (const d of devices) {
    const m = mac(d.macAddress) ?? d.macAddress.toLowerCase();
    scope.devices.set(d.id, { mac: m, name: d.name });
    if (isGatewayModel(d.model) || gatewayMacs.has(m)) {
      scope.gatewayDeviceIds.add(d.id).add(m);
    } else if (carrying.has(m)) {
      scope.uplinkDeviceIds.add(d.id).add(m);
    }
  }
  return scope;
}

// ---- the check -------------------------------------------------------------

function subnetOf(ip: string, scope: ProtectedScope) {
  const n = ipv4(ip);
  return n === undefined ? undefined : scope.subnets.find((s) => inCidr(n, s.cidr));
}

/** The protected network a client is on, by network id or by IP. */
function clientNetwork(c: KnownClient, scope: ProtectedScope): string | undefined {
  if (c.networkId !== undefined && scope.networkIds.has(c.networkId)) {
    return scope.networkNames.get(c.networkId);
  }
  return c.ip === undefined ? undefined : subnetOf(c.ip, scope)?.network;
}

const cantPlace = (what: string) => `can't place ${what} so it may be on a protected network`;

const clientLabel = (c: KnownClient) => (c.ip ? `${c.name} (${c.ip})` : c.name);

function findDevice(
  id: string,
  scope: ProtectedScope,
): { id?: string; mac?: string; name: string } {
  const byId = scope.devices.get(id);
  if (byId) return { id, mac: byId.mac, name: byId.name };
  const m = mac(id);
  for (const [deviceId, d] of scope.devices) {
    if (m !== undefined && d.mac === m) return { id: deviceId, mac: d.mac, name: d.name };
  }
  return { mac: m, name: id };
}

const isIn = (set: Set<string>, d: { id?: string; mac?: string }) =>
  (d.id !== undefined && set.has(d.id)) || (d.mac !== undefined && set.has(d.mac));

/** Protected clients hanging off a device (by its MAC), optionally on one port. */
function protectedBehind(
  devMac: string | undefined,
  port: number | undefined,
  scope: ProtectedScope,
  clients: KnownClient[],
) {
  return clients.filter(
    (c) =>
      sameMac(c.uplinkMac, devMac) &&
      (port === undefined || c.uplinkPort === port) &&
      clientNetwork(c, scope) !== undefined,
  );
}

function describeBehind(behind: KnownClient[], scope: ProtectedScope): string {
  const nets = [...new Set(behind.map((c) => clientNetwork(c, scope)))].join(', ');
  const shown = behind.slice(0, 3).map(clientLabel).join(', ');
  const more = behind.length > 3 ? ` and ${behind.length - 3} more` : '';
  return `${shown}${more} on ${nets}`;
}

/**
 * Why a change to `target` could cut unifi-mcp off from the console, or
 * undefined when it can't. Pure: everything it knows comes from the scope and
 * the client list. When it can't tell (an address it can't place, a switch
 * port with no known client on a switch that carries a protected network),
 * it says so rather than letting the change through as easy.
 */
export function touchesProtected(
  target: Target,
  scope: ProtectedScope,
  clients: KnownClient[],
): string | undefined {
  switch (target.kind) {
    case 'network': {
      const name =
        scope.networkNames.get(target.id) ??
        [...scope.networkNames.values()].find((n) => n.toLowerCase() === target.id.toLowerCase());
      return name === undefined ? undefined : `it changes ${name}, a protected network`;
    }

    case 'policy': {
      const hit = (ids: string[]) => [
        ...new Set(
          ids.filter((id) => scope.networkIds.has(id)).map((id) => scope.networkNames.get(id)),
        ),
      ];
      const src = hit(target.sourceNetworkIds);
      const dst = hit(target.destNetworkIds);
      if (dst.length)
        return `the policy's destination includes ${dst.join(', ')}, a protected network`;
      if (src.length) return `the policy's source includes ${src.join(', ')}, a protected network`;
      return undefined;
    }

    case 'ip': {
      const subnet = subnetOf(target.ip, scope);
      if (subnet)
        return `${target.ip} is inside ${subnet.network} (${subnet.cidr}), a protected network`;
      if (ipv4(target.ip) === undefined && scope.subnets.length > 0) {
        return `${target.ip} is not an IPv4 address unifi-mcp can place, so it may belong to a protected network`;
      }
      const owner = clients.find(
        (c) => c.ip === target.ip && clientNetwork(c, scope) !== undefined,
      );
      return owner
        ? `${target.ip} belongs to ${clientLabel(owner)} on ${clientNetwork(owner, scope)}`
        : undefined;
    }

    case 'client': {
      // With nothing protected there is nothing a client could be on.
      if (scope.networkIds.size === 0) return undefined;
      const asMac = mac(target.ipOrMac);
      const asIp = asMac ? undefined : ipv4(target.ipOrMac);
      if (asMac === undefined && asIp === undefined) return cantPlace(`client "${target.ipOrMac}"`);
      const c = clients.find((k) => (asMac ? sameMac(k.mac, asMac) : k.ip === target.ipOrMac));
      if (c) {
        const net = clientNetwork(c, scope);
        if (net !== undefined) return `client ${clientLabel(c)} is on ${net}, a protected network`;
        if (c.networkId === undefined && c.ip === undefined) {
          return cantPlace(`client ${c.name}, which has neither a network nor an IP,`);
        }
        return undefined;
      }
      if (asMac) return cantPlace(`client ${target.ipOrMac}, which the console does not know,`);
      const subnet = subnetOf(target.ipOrMac, scope);
      return subnet
        ? `${target.ipOrMac} is inside ${subnet.network} (${subnet.cidr}), a protected network`
        : undefined;
    }

    case 'device': {
      const d = findDevice(target.id, scope);
      // An unknown device could be the gateway itself.
      if (d.id === undefined)
        return cantPlace(`device "${target.id}", which unifi-mcp does not know,`);
      if (isIn(scope.gatewayDeviceIds, d))
        return `${d.name} is the gateway, unifi-mcp's way into the console`;
      const behind = protectedBehind(d.mac, undefined, scope, clients);
      if (isIn(scope.uplinkDeviceIds, d) || behind.length) {
        return behind.length
          ? `${d.name} carries ${describeBehind(behind, scope)}`
          : `${d.name} carries clients of a protected network`;
      }
      return undefined;
    }

    case 'port': {
      const d = findDevice(target.deviceId, scope);
      if (d.id === undefined) {
        return cantPlace(
          `port ${target.portIdx} on "${target.deviceId}", a device unifi-mcp does not know,`,
        );
      }
      const where = `port ${target.portIdx} on ${d.name}`;
      if (isIn(scope.gatewayDeviceIds, d))
        return `${where}: a port on the gateway, unifi-mcp's way into the console`;
      const onPort = protectedBehind(d.mac, target.portIdx, scope, clients);
      if (onPort.length) return `${where} feeds ${describeBehind(onPort, scope)}`;
      const carries =
        isIn(scope.uplinkDeviceIds, d) ||
        protectedBehind(d.mac, undefined, scope, clients).length > 0;
      const anyoneOnPort = clients.some(
        (c) => sameMac(c.uplinkMac, d.mac) && c.uplinkPort === target.portIdx,
      );
      if (carries && !anyoneOnPort) {
        return `${where} has no known client and ${d.name} carries a protected network: it could be its uplink`;
      }
      return undefined;
    }
  }
}

/**
 * Runs a change only at the level it deserves. `easy` runs at once unless the
 * target touches a protected network, which raises it to `confirm`. At
 * `confirm`, a call without the literal `confirm: true` gets the preview
 * (built by `preview`, which must not write) and `run` is never called. A
 * confirmed change that touched a protected network repeats the warning.
 */
export async function guarded<T>(
  args: {
    level: Guard;
    target?: Target;
    confirm?: true;
    preview: () => Promise<object>;
    run: () => Promise<T>;
  },
  scope: ProtectedScope,
  clients: KnownClient[],
): Promise<T | GuardPreview | { result: T; warning: string }> {
  const reason =
    args.target === undefined ? undefined : touchesProtected(args.target, scope, clients);
  const warning = reason === undefined ? undefined : `${CUT_OFF_WARNING} ${reason}`;
  const level: Guard = warning === undefined ? args.level : 'confirm';

  if (level === 'easy') return args.run();
  // Strict: a JS caller passing "true" or 1 gets the preview, not the change.
  if (args.confirm !== true) {
    const preview = await args.preview();
    return { ...(warning === undefined ? {} : { warning }), preview, requires: 'confirm: true' };
  }
  const result = await args.run();
  if (warning === undefined) return result;
  // A result with its own `warning` is wrapped, never overwritten.
  if (
    result !== null &&
    typeof result === 'object' &&
    !Array.isArray(result) &&
    !('warning' in result)
  )
    return { ...result, warning };
  return { result, warning };
}
