export type TransportMode = 'stdio' | 'http' | 'both';

export type TlsConfig = { fingerprint: string } | { insecure: true };

export interface ConsoleConnection {
  baseUrl: string;
  apiKey: string;
  tls: TlsConfig;
}

export interface UnifiMcpConfig {
  console: ConsoleConnection;
  siteManagerApiKey?: string;
  readOnly: boolean;
  /** Network names or ids whose changes need confirm-level handling. */
  protectedNetworks: string[];
  transport: TransportMode;
  port: number;
  token?: string;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const TRANSPORTS: readonly TransportMode[] = ['stdio', 'http', 'both'];
const DEFAULT_PROTECTED_NETWORKS = ['pi-cluster'];

function readBoolean(env: NodeJS.ProcessEnv, name: string): boolean {
  const raw = env[name]?.trim().toLowerCase();
  if (!raw) return false;
  if (raw === 'true' || raw === '1') return true;
  if (raw === 'false' || raw === '0') return false;
  throw new ConfigError(`${name} must be true, false, 1 or 0 (got: ${raw})`);
}

function normaliseFingerprint(raw: string): string {
  const hex = raw.replace(/:/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new ConfigError('UNIFI_TLS_FINGERPRINT must be a SHA-256 fingerprint (64 hex digits)');
  }
  return hex.toUpperCase().match(/.{2}/g)!.join(':');
}

function readTls(env: NodeJS.ProcessEnv): TlsConfig {
  if (readBoolean(env, 'UNIFI_TLS_INSECURE')) return { insecure: true };
  const raw = env.UNIFI_TLS_FINGERPRINT?.trim();
  if (!raw) {
    throw new ConfigError(
      'UNIFI_TLS_FINGERPRINT is required (or set UNIFI_TLS_INSECURE=true for local experiments)',
    );
  }
  return { fingerprint: normaliseFingerprint(raw) };
}

function readConnection(env: NodeJS.ProcessEnv): ConsoleConnection {
  const rawUrl = env.UNIFI_URL?.trim();
  const apiKey = env.UNIFI_API_KEY?.trim();
  if (!rawUrl) throw new ConfigError('UNIFI_URL is required');
  if (!apiKey) throw new ConfigError('UNIFI_API_KEY is required');

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    // The raw value is not echoed: it could carry userinfo.
    throw new ConfigError('UNIFI_URL is not a valid URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('UNIFI_URL must use https:// (or http://)');
  }
  // Undici puts the full URL in its connection errors, so userinfo would leak.
  if (url.username || url.password) throw new ConfigError('UNIFI_URL must not contain credentials');

  const tls = readTls(env);
  if ('fingerprint' in tls && url.protocol !== 'https:') {
    throw new ConfigError('UNIFI_URL must use https:// when UNIFI_TLS_FINGERPRINT is set');
  }
  return { baseUrl: rawUrl.replace(/\/+$/, ''), apiKey, tls };
}

/**
 * Unset means the default. An empty value is an error rather than "nothing
 * protected", since it is more often a templating slip than a choice; `none`
 * says the choice out loud (only the gateway stays protected).
 */
function readProtectedNetworks(env: NodeJS.ProcessEnv): string[] {
  const raw = env.UNIFI_MCP_PROTECTED_NETWORKS;
  if (raw === undefined) return [...DEFAULT_PROTECTED_NETWORKS];
  if (raw.trim().toLowerCase() === 'none') return [];
  const names = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (names.length === 0) {
    throw new ConfigError(
      'UNIFI_MCP_PROTECTED_NETWORKS is empty; set network names, or "none" to protect only the gateway',
    );
  }
  return names;
}

/** The startup line naming what the guard protects; a warning when it is only the gateway. */
export function protectedNetworksLog(networks: readonly string[]): string {
  return networks.length === 0
    ? 'unifi-mcp: WARNING: protected networks: none (gateway only)'
    : `unifi-mcp: protected networks: ${networks.join(', ')}`;
}

function readTransport(env: NodeJS.ProcessEnv): TransportMode {
  const raw = env.UNIFI_MCP_TRANSPORT?.trim();
  if (!raw) return 'stdio';
  if (!TRANSPORTS.includes(raw as TransportMode)) {
    throw new ConfigError(`UNIFI_MCP_TRANSPORT must be one of ${TRANSPORTS.join(', ')} (got: ${raw})`);
  }
  return raw as TransportMode;
}

function readPort(env: NodeJS.ProcessEnv): number {
  const raw = env.UNIFI_MCP_PORT?.trim();
  if (!raw) return 3000;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError(`UNIFI_MCP_PORT must be an integer between 1 and 65535 (got: ${raw})`);
  }
  return port;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): UnifiMcpConfig {
  const console = readConnection(env);
  const transport = readTransport(env);
  const token = env.UNIFI_MCP_TOKEN?.trim() || undefined;

  if ((transport === 'http' || transport === 'both') && !token) {
    throw new ConfigError(`UNIFI_MCP_TOKEN is required when UNIFI_MCP_TRANSPORT is "${transport}"`);
  }

  return {
    console,
    siteManagerApiKey: env.UNIFI_SITE_MANAGER_API_KEY?.trim() || undefined,
    readOnly: readBoolean(env, 'UNIFI_MCP_READ_ONLY'),
    protectedNetworks: readProtectedNetworks(env),
    transport,
    port: readPort(env),
    token,
  };
}
