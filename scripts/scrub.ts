/**
 * Scrubs live console responses before they are committed as fixtures. The
 * repo is public, so anything that identifies the owner, their account, their
 * console, their neighbours or the outside world reaching them is replaced:
 *
 * - MACs → 02:00:00:00:00:NN (also their compact form, e.g. in serials)
 * - public IPv4 → 203.0.113.N (then the other RFC 5737 blocks, then 198.18/15);
 *   private ranges are kept. Global IPv6 → 2001:db8::N; EUI-64 link-locals,
 *   which embed a MAC, → fe80::ff:fe00:N
 * - the console's own name → CONSOLE_NAME (its real name can reveal the owner's
 *   DDNS label); client, device, SSID and account names → client-N, device-N,
 *   ssid-N, user-N, except ALLOWED_NAMES, which the tests rely on
 * - emails → user-N@example.com; DDNS and per-console cloud hostnames →
 *   host-N.example.net; location → redacted
 * - serials, anonymous ids, account ids and the cloud host id → same-shaped fakes
 * - secrets (`x_*`, `*key*`, `*secret*`, `*passw*`, `*token*`, `psk`) → "<redacted>"
 *
 * The map is deterministic: the same input, in the same order, always gets the
 * same fakes, and one map is shared across files so they stay consistent.
 */

export const REDACTED = '<redacted>';
/** What the console (the gateway itself) is called in the fixtures. */
export const CONSOLE_NAME = 'Gateway CGU';

/** Names kept as they are: the tests and the spec refer to them. */
export const ALLOWED_NAMES: ReadonlySet<string> = new Set([
  'pi-cluster',
  'data-archive',
  'MAC Hub',
  CONSOLE_NAME,
  'Default',
  'IoT',
  'Synology',
]);

/** Public resolvers that identify nobody and that config checks may look for. */
const WELL_KNOWN_IPS: ReadonlySet<string> = new Set([
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
]);

type NameKind = 'console' | 'client' | 'device' | 'ssid' | 'user';

export interface ScrubMap {
  readonly macs: Map<string, string>;
  readonly ipv4: Map<string, string>;
  readonly ipv6: Map<string, string>;
  readonly linkLocal: Map<string, string>;
  readonly emails: Map<string, string>;
  readonly hosts: Map<string, string>;
  readonly ids: Map<string, string>;
  readonly names: Map<string, string>;
  readonly nameCounts: Record<NameKind, number>;
  /** Every fake id handed out, so scrubbing a fixture again leaves it alone. */
  readonly fakeIds: Set<string>;
  /**
   * Real official-API site ids: they sit inside request paths too, so every
   * string has them replaced (by their fake in `ids`), not only id fields.
   */
  readonly siteIds: Set<string>;
  /** Derived lookups, rebuilt only when a table grows. */
  readonly cache: { namesSize: number; names: string[]; macsSize: number; compact?: RegExp };
}

export function createScrubMap(): ScrubMap {
  return {
    macs: new Map(),
    ipv4: new Map(),
    ipv6: new Map(),
    linkLocal: new Map(),
    emails: new Map(),
    hosts: new Map(),
    ids: new Map(),
    names: new Map(),
    nameCounts: { console: 0, client: 0, device: 0, ssid: 0, user: 0 },
    fakeIds: new Set(),
    siteIds: new Set(),
    cache: { namesSize: -1, names: [], macsSize: -1 },
  };
}

// ---------------------------------------------------------------- patterns

const MAC_RE = /(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])/gi;
const ONE_MAC_RE = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const HAS_MAC_RE = /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i;
const COMPACT_MAC_RE = /^[0-9a-f]{12}$/i;
const IPV4_RE = /(?<![\w.]|\w\.)(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w)/g;
const IPV6_GLOBAL_RE = /(?<![0-9a-f:])[23][0-9a-f]{3}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])/gi;
const EUI64_LINK_LOCAL_RE =
  /(?<![0-9a-f:])fe80::(?:[0-9a-f]{1,4}:)?[0-9a-f]{0,2}ff:fe[0-9a-f]{0,2}:[0-9a-f]{1,4}(?![0-9a-f:])/gi;
const EMAIL_RE = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
/** UniFi cloud host id: a long hex string, a colon, then digits. */
const CLOUD_ID_RE = /(?<![0-9a-f])[0-9a-f]{40,}:\d+(?!\d)/gi;
/** Dynamic DNS and the per-console cloud domain: every name under them is someone's. */
const PRIVATE_DNS_RE =
  /(?<![\w.-])(?:[a-z0-9-]+\.)+(?:myds\.me|synology\.me|ui\.direct|duckdns\.org|ddns\.net|dyndns\.org|no-ip\.(?:com|org|biz)|hopto\.org|freeddns\.org|dynu\.net|myfritz\.net)(?![\w-]|\.\w)/gi;
const MAC_TAIL_RE = /^(.*) ([0-9a-f]{2}:[0-9a-f]{2})$/i;
const PORT_SUFFIX_RE = /^(.*) Port \d+$/;

const SECRET_KEY_RE = /^x_|key|secret|passw|token|^psk$|passphrase|private/i;
const ID_KEY_RE =
  /^(?:serial(?:no|_?number)?|hardwareId|uuid|controller_uuid|localId|roleId|anonid|anon_.+|anonymous_.+|sso_.+|qrid|cloud_?id|owner_?id|account_?id|admin_?id|user_?uuid)$/i;
const LOCATION_KEY_RE = /^(?:location|latitude|longitude|lat|lng|long|gps.*|geo.*)$/i;
const FREE_TEXT_KEY_RE = /^(?:note|notes)$/i;
/** Fields holding version strings, which can look like IPv4 ("4.0.6.1"). Not `fwd`. */
const VERSION_KEY_RE = /version|(?:^|_)build$|^firmware/i;
/** An audit entry's SECTION that makes its OBJECT name a partial credential. */
const SECRET_SECTION_RE = /TOKEN|KEY|SECRET|PASSW/i;
/** Product vocabulary: a device named after its model must not rename the model. */
const PRODUCT_KEY_RE = /^(?:model|model_name|modelName|shortname|ubnt_device_type|sku|oui|type)$/i;

/** Keys whose value is always this kind of name, wherever they appear. */
const NAME_KEYS: Record<string, NameKind> = {
  hostname: 'client',
  host_name: 'client',
  hostName: 'client',
  essid: 'ssid',
  ssid: 'ssid',
  wlan_name: 'ssid',
  gw_name: 'console',
  last_uplink_name: 'device',
  uplink_name: 'device',
  uplink_device_name: 'device',
  ap_name: 'device',
  sw_name: 'device',
  device_name: 'device',
  deviceName: 'device',
  fullName: 'user',
  full_name: 'user',
  firstName: 'user',
  first_name: 'user',
  lastName: 'user',
  last_name: 'user',
  username: 'user',
  user_name: 'user',
};
/** Keys that are a name only when the object they sit in says what it is. */
const CONTEXT_NAME_KEYS = new Set(['name', 'display_name', 'displayName', 'alias']);
/** System-log parameter keys that say what their {id, name} object is. */
const PARAM_KINDS: Record<string, NameKind> = {
  CLIENT: 'client',
  SRC_CLIENT: 'client',
  DST_CLIENT: 'client',
  GUEST: 'client',
  DEVICE: 'device',
  DEVICE_WITH_PORT: 'device',
  CONSOLE_NAME: 'console',
  CONSOLE_WITH_DEVICE_NAME: 'device',
  AP: 'device',
  SWITCH: 'device',
  GATEWAY: 'device',
  WLAN: 'ssid',
  SSID: 'ssid',
  ADMIN: 'user',
  USER: 'user',
};
const ACCOUNT_PARAMS = new Set(['ADMIN', 'USER']);
const DEVICE_TYPES = new Set(['uap', 'usw', 'ugw', 'udm', 'uxg', 'ucg', 'udr']);
const CONSOLE_TYPES = new Set(['ugw', 'udm', 'uxg', 'ucg', 'udr']);

// ---------------------------------------------------------------- fakes

const hex = (n: number, width: number) => n.toString(16).padStart(width, '0');

function fakeMac(n: number): string {
  // 02 = locally administered. Up to 255 MACs this is exactly 02:00:00:00:00:NN.
  return `02:00:00:00:${hex(n >> 8, 2)}:${hex(n & 0xff, 2)}`;
}

function fakeIpv4(n: number): string {
  if (n <= 254) return `203.0.113.${n}`;
  if (n <= 508) return `198.51.100.${n - 254}`;
  if (n <= 762) return `192.0.2.${n - 508}`;
  const m = n - 762; // 198.18.0.0/15, the benchmarking block: neither private nor routable
  return `198.${18 + (m >> 16)}.${(m >> 8) & 0xff}.${m & 0xff}`;
}

function isDocumentationIp(ip: string): boolean {
  return /^(?:203\.0\.113|198\.51\.100|192\.0\.2)\.|^198\.1[89]\./.test(ip);
}

function isPrivateOrSpecialIpv4(ip: string): boolean {
  const octets = ip.split('.').map(Number);
  if (octets.some((o) => o > 255)) return true; // not an address at all
  const [a, b] = octets as [number, number, number, number];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 || // multicast, reserved, broadcast and netmasks
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    WELL_KNOWN_IPS.has(ip) ||
    isDocumentationIp(ip)
  );
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FAKE_UUID_PREFIX = '00000000-0000-4000-8000-';

function fakeId(original: string, n: number): string {
  if (UUID_RE.test(original)) {
    return `${FAKE_UUID_PREFIX}${hex(n, 12)}`;
  }
  const cloud = /^([0-9a-f]{40,}):(\d+)$/i.exec(original);
  if (cloud) return `${hex(n, cloud[1]!.length).toUpperCase()}:${n}`;
  if (/^[0-9a-f]+$/i.test(original)) {
    const out = hex(n, original.length);
    return original === original.toUpperCase() ? out.toUpperCase() : out;
  }
  return `id-${n}`;
}

function intern(table: Map<string, string>, key: string, make: (n: number) => string): string {
  let fake = table.get(key);
  if (fake === undefined) {
    fake = make(table.size + 1);
    table.set(key, fake);
  }
  return fake;
}

const isFakeMac = (mac: string) => mac.startsWith('02:00:00:00:');
const macKey = (mac: string) => mac.toLowerCase();

function mapMac(map: ScrubMap, mac: string): string {
  return isFakeMac(mac) ? mac : intern(map.macs, macKey(mac), fakeMac);
}

function mapId(map: ScrubMap, id: string): string {
  if (map.fakeIds.has(id) || id.startsWith(FAKE_UUID_PREFIX)) return id;
  const fake = intern(map.ids, id, (n) => fakeId(id, n));
  map.fakeIds.add(fake);
  return fake;
}

function isFakeName(name: string): boolean {
  return /^(?:client|device|ssid|user)-\d+$/.test(name);
}

// ---------------------------------------------------------------- learning

function realMacOf(record: Record<string, unknown>): string | undefined {
  for (const key of ['mac', 'macAddress', 'id']) {
    const value = record[key];
    if (typeof value === 'string' && ONE_MAC_RE.test(value)) return value;
  }
  return undefined;
}

/** What kind of thing an object is, judged by its own fields and the key it sits under. */
function objectKind(
  record: Record<string, unknown>,
  parentKey: string | undefined,
): NameKind | undefined {
  const fromParam = parentKey === undefined ? undefined : PARAM_KINDS[parentKey];
  if (fromParam) return fromParam;
  if (parentKey === 'hardware') return undefined; // the product, not this unit
  const has = (key: string) => key in record;
  const type = typeof record.type === 'string' ? record.type.toLowerCase() : '';
  // The console itself: sysinfo, Site Manager's reportedState, a gateway in the device list.
  if (has('ubnt_device_type') || has('hardware') || CONSOLE_TYPES.has(type)) return 'console';
  if (has('x_passphrase') || has('securityConfiguration') || has('wpa_mode') || has('essid')) {
    return 'ssid';
  }
  const hasMac = has('mac') || has('macAddress');
  if (
    (has('model') && (hasMac || has('serial') || has('id'))) ||
    has('firmwareVersion') ||
    has('model_name') ||
    (hasMac && DEVICE_TYPES.has(type))
  ) {
    return 'device';
  }
  if (hasMac || has('oui') || has('hostname')) return 'client';
  return undefined;
}

/** The name without the " xx:yy" MAC tail or " Port N" label UniFi appends. */
function baseName(name: string, realMac: string | undefined): string {
  const tail = MAC_TAIL_RE.exec(name);
  if (tail && realMac && realMac.toLowerCase().endsWith(tail[2]!.toLowerCase())) return tail[1]!;
  const port = PORT_SUFFIX_RE.exec(name);
  return port ? port[1]! : name;
}

function learnName(map: ScrubMap, name: string, kind: NameKind): void {
  const trimmed = name.trim();
  if (kind === 'console') {
    // Overrides an earlier guess (a gateway in the device list looks like any device).
    if (!trimmed || trimmed === CONSOLE_NAME || /^Gateway CGU \d+$/.test(trimmed)) return;
    const known = map.names.get(trimmed);
    if (known === CONSOLE_NAME || known?.startsWith(`${CONSOLE_NAME} `)) return;
    map.nameCounts.console += 1;
    const n = map.nameCounts.console;
    map.names.set(trimmed, n === 1 ? CONSOLE_NAME : `${CONSOLE_NAME} ${n}`);
    return;
  }
  if (!trimmed || ALLOWED_NAMES.has(trimmed) || isFakeName(trimmed) || map.names.has(trimmed))
    return;
  // An address standing in for a name: the address rules handle it.
  if (HAS_MAC_RE.test(trimmed) || /^[\d.:/]+$/.test(trimmed)) return;
  map.nameCounts[kind] += 1;
  map.names.set(trimmed, `${kind}-${map.nameCounts[kind]}`);
}

function learnValue(value: unknown, map: ScrubMap, parentKey: string | undefined): void {
  if (Array.isArray(value)) {
    for (const item of value) learnValue(item, map, parentKey);
    return;
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string') {
      for (const mac of value.match(MAC_RE) ?? []) mapMac(map, mac);
    }
    return;
  }
  const record = value as Record<string, unknown>;
  // An official-API site ({id, internalReference, name}): its id names the owner's console.
  const siteId = record.id;
  if (typeof record.internalReference === 'string' && typeof siteId === 'string' && UUID_RE.test(siteId)) {
    if (!siteId.startsWith(FAKE_UUID_PREFIX)) map.siteIds.add(siteId);
    mapId(map, siteId);
  }
  const kind = objectKind(record, parentKey);
  const realMac = realMacOf(record);
  for (const [key, child] of Object.entries(record)) {
    if (typeof child === 'string') {
      const fixedKind = NAME_KEYS[key];
      if (fixedKind) {
        // A device's (or the console's) own hostname is a device name.
        const isDevice = kind === 'device' || kind === 'console';
        const named = isDevice && fixedKind === 'client' ? 'device' : fixedKind;
        learnName(map, baseName(child, realMac), named);
      } else if (kind && CONTEXT_NAME_KEYS.has(key)) {
        learnName(map, baseName(child, realMac), kind);
      }
    }
    learnValue(child, map, key);
  }
}

/**
 * Learns the names and MACs in `value` without rewriting it. Prime the map with
 * every file before scrubbing any, so a name first seen in a later file is
 * still replaced in an earlier one.
 */
export function prime(value: unknown, map: ScrubMap): void {
  learnValue(value, map, undefined);
}

// ---------------------------------------------------------------- rewriting

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Learned names inside free text, longest first, on word boundaries. */
function replaceNames(text: string, map: ScrubMap): string {
  const exact = map.names.get(text);
  if (exact) return exact;
  if (ALLOWED_NAMES.has(text)) return text;
  let out = text;
  if (map.cache.namesSize !== map.names.size) {
    // Short names would hit ordinary words; they are still replaced when they are the whole value.
    map.cache.names = [...map.names.keys()]
      .filter((n) => n.length >= 4)
      .sort((a, b) => b.length - a.length);
    map.cache.namesSize = map.names.size;
  }
  for (const name of map.cache.names) {
    if (!out.includes(name)) continue;
    const re = new RegExp(`(?<![\\w-])${escapeRegExp(name)}(?![\\w-])`, 'g');
    out = out.replace(re, map.names.get(name)!);
  }
  return out;
}

function replaceAddresses(text: string, map: ScrubMap, versionLike: boolean): string {
  let out = text
    .replace(EMAIL_RE, (email) =>
      email.endsWith('@example.com')
        ? email
        : intern(map.emails, email.toLowerCase(), (n) => `user-${n}@example.com`),
    )
    .replace(PRIVATE_DNS_RE, (host) =>
      intern(map.hosts, host.toLowerCase(), (n) => `host-${n}.example.net`),
    )
    .replace(CLOUD_ID_RE, (id) => mapId(map, id))
    .replace(MAC_RE, (mac) => mapMac(map, mac))
    .replace(EUI64_LINK_LOCAL_RE, (ll) =>
      intern(map.linkLocal, ll.toLowerCase(), (n) => `fe80::ff:fe00:${hex(n, 1)}`),
    )
    .replace(IPV6_GLOBAL_RE, (ip) =>
      ip.toLowerCase().startsWith('2001:db8:')
        ? ip
        : intern(map.ipv6, ip.toLowerCase(), (n) => `2001:db8::${hex(n, 1)}`),
    );
  if (!versionLike) {
    out = out.replace(IPV4_RE, (ip) =>
      isPrivateOrSpecialIpv4(ip) ? ip : intern(map.ipv4, ip, fakeIpv4),
    );
  }
  // The compact form of a known MAC (serials, host ids, hardware.mac).
  const compact = compactMacPattern(map);
  if (compact) {
    out = out.replace(compact, (hit) => {
      const fake = map.macs.get(macKey(colonise(hit)))!.replace(/:/g, '');
      return hit === hit.toUpperCase() ? fake.toUpperCase() : fake;
    });
  }
  return out;
}

const colonise = (compact: string) => compact.replace(/(..)(?!$)/g, '$1:');

function compactMacPattern(map: ScrubMap): RegExp | undefined {
  if (map.cache.macsSize !== map.macs.size) {
    const reals = [...map.macs.keys()].map((mac) => mac.replace(/:/g, ''));
    map.cache.compact = reals.length ? new RegExp(reals.join('|'), 'gi') : undefined;
    map.cache.macsSize = map.macs.size;
  }
  return map.cache.compact;
}

function scrubString(raw: string, key: string | undefined, map: ScrubMap): string {
  let text = raw;
  for (const id of map.siteIds) if (text.includes(id)) text = text.replaceAll(id, mapId(map, id));
  if (key !== undefined && key !== 'key' && SECRET_KEY_RE.test(key)) return text ? REDACTED : text;
  if (key !== undefined && FREE_TEXT_KEY_RE.test(key)) return text ? REDACTED : text;
  if (key !== undefined && ID_KEY_RE.test(key) && text) {
    if (COMPACT_MAC_RE.test(text) && map.macs.has(macKey(colonise(text)))) {
      return replaceAddresses(text, map, true);
    }
    return mapId(map, text);
  }
  if (key !== undefined && /mac/i.test(key) && COMPACT_MAC_RE.test(text)) {
    const fake = mapMac(map, colonise(text)).replace(/:/g, '');
    return text === text.toUpperCase() ? fake.toUpperCase() : fake;
  }
  // Whole learned names first: a hostname can embed a MAC the address rules would half-rewrite.
  const learned = map.names.get(text.trim());
  if (learned && !(key !== undefined && PRODUCT_KEY_RE.test(key))) return learned;
  const versionLike = key !== undefined && VERSION_KEY_RE.test(key);
  const addressed = replaceAddresses(text, map, versionLike);
  return key !== undefined && PRODUCT_KEY_RE.test(key) ? addressed : replaceNames(addressed, map);
}

/** A name with UniFi's " xx:yy" MAC tail: the base and the tail are mapped apart. */
function scrubTailedName(name: string, realMac: string, map: ScrubMap): string | undefined {
  const tail = MAC_TAIL_RE.exec(name);
  if (!tail || !realMac.toLowerCase().endsWith(tail[2]!.toLowerCase())) return undefined;
  const base = replaceNames(replaceAddresses(tail[1]!, map, false), map);
  return `${base} ${mapMac(map, realMac).slice(-5)}`;
}

function scrubValue(
  value: unknown,
  map: ScrubMap,
  key: string | undefined,
  inSecret: boolean,
  inLocation: boolean,
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => scrubValue(item, map, key, inSecret, inLocation));
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const realMac = realMacOf(record);
    const accountParam = key !== undefined && ACCOUNT_PARAMS.has(key);
    const section = record.SECTION as { id?: unknown } | undefined;
    const secretObject = typeof section?.id === 'string' && SECRET_SECTION_RE.test(section.id);
    const out: Record<string, unknown> = {};
    for (const [childKey, child] of Object.entries(record)) {
      if (typeof child === 'string' && realMac && CONTEXT_NAME_KEYS.has(childKey)) {
        const tailed = scrubTailedName(child, realMac, map);
        if (tailed !== undefined) {
          out[childKey] = tailed;
          continue;
        }
      }
      if (secretObject && childKey === 'OBJECT' && child && typeof child === 'object') {
        const object = { ...(child as Record<string, unknown>) };
        if (typeof object.name === 'string') object.name = REDACTED;
        out[childKey] = scrubValue(object, map, childKey, inSecret, inLocation);
        continue;
      }
      if (accountParam && childKey === 'id' && typeof child === 'string') {
        out[childKey] = mapId(map, child);
        continue;
      }
      const secret = inSecret || (childKey !== 'key' && SECRET_KEY_RE.test(childKey));
      if (secret && typeof child === 'number' && !inSecret && !childKey.startsWith('x_')) {
        out[childKey] = child; // an interval or a count (group_rekey), not a secret
        continue;
      }
      const location = inLocation || LOCATION_KEY_RE.test(childKey);
      out[childKey] = scrubValue(child, map, childKey, secret, location);
    }
    return out;
  }
  if (inLocation && typeof value === 'number') return 0;
  if (typeof value === 'number' && inSecret) return REDACTED;
  if (typeof value !== 'string') return value;
  if (inSecret || inLocation) return value ? REDACTED : value;
  return scrubString(value, key, map);
}

/** Returns a scrubbed copy of `value`; the input is not changed. */
export function scrub(value: unknown, map: ScrubMap): unknown {
  prime(value, map);
  return scrubValue(value, map, undefined, false, false);
}
