import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, protectedNetworksLog } from '../src/config.js';

const FP = 'AA:BB:CC:' + 'AB:'.repeat(28) + 'CD';
const base = {
  UNIFI_URL: 'https://192.168.0.1',
  UNIFI_API_KEY: 'api-key',
  UNIFI_TLS_FINGERPRINT: FP,
};

describe('loadConfig', () => {
  it('reads the console connection and defaults', () => {
    expect(loadConfig({ ...base })).toEqual({
      console: { baseUrl: 'https://192.168.0.1', apiKey: 'api-key', tls: { fingerprint: FP } },
      siteManagerApiKey: undefined,
      readOnly: false,
      protectedNetworks: ['pi-cluster'],
      transport: 'stdio',
      port: 3000,
      token: undefined,
    });
  });

  it('requires UNIFI_URL', () => {
    expect(() => loadConfig({ UNIFI_API_KEY: 'k' })).toThrow(new ConfigError('UNIFI_URL is required'));
  });

  it('requires UNIFI_API_KEY', () => {
    expect(() => loadConfig({ UNIFI_URL: 'https://c.test' })).toThrow(new ConfigError('UNIFI_API_KEY is required'));
  });

  it('rejects an invalid URL', () => {
    expect(() => loadConfig({ ...base, UNIFI_URL: 'not a url' })).toThrow(/UNIFI_URL is not a valid URL/);
  });

  it('does not echo an invalid URL, which could hold credentials', () => {
    expect(() => loadConfig({ ...base, UNIFI_URL: 'https://admin:hunter2@[bad' })).toThrow(
      new ConfigError('UNIFI_URL is not a valid URL'),
    );
  });

  it('rejects schemes other than https and http', () => {
    expect(() => loadConfig({ ...base, UNIFI_URL: 'ftp://192.168.0.1' })).toThrow(
      new ConfigError('UNIFI_URL must use https:// (or http://)'),
    );
    const insecure = { UNIFI_URL: 'http://192.168.0.1', UNIFI_API_KEY: 'k', UNIFI_TLS_INSECURE: 'true' };
    expect(loadConfig(insecure).console.baseUrl).toBe('http://192.168.0.1');
  });

  it('rejects http:// when a fingerprint is set, since nothing could be pinned', () => {
    expect(() => loadConfig({ ...base, UNIFI_URL: 'http://192.168.0.1' })).toThrow(
      new ConfigError('UNIFI_URL must use https:// when UNIFI_TLS_FINGERPRINT is set'),
    );
  });

  it('rejects credentials in UNIFI_URL', () => {
    expect(() => loadConfig({ ...base, UNIFI_URL: 'https://admin:hunter2@192.168.0.1' })).toThrow(
      new ConfigError('UNIFI_URL must not contain credentials'),
    );
    expect(() => loadConfig({ ...base, UNIFI_URL: 'https://admin@192.168.0.1' })).toThrow(
      new ConfigError('UNIFI_URL must not contain credentials'),
    );
  });

  it('strips trailing slashes', () => {
    expect(loadConfig({ ...base, UNIFI_URL: 'https://192.168.0.1//' }).console.baseUrl).toBe('https://192.168.0.1');
  });

  it('requires a fingerprint unless insecure', () => {
    const noFp = { UNIFI_URL: base.UNIFI_URL, UNIFI_API_KEY: base.UNIFI_API_KEY };
    expect(() => loadConfig(noFp)).toThrow(
      new ConfigError('UNIFI_TLS_FINGERPRINT is required (or set UNIFI_TLS_INSECURE=true for local experiments)'),
    );
  });

  it('normalises the fingerprint to upper-case colon-separated', () => {
    const hex = 'ab'.repeat(32);
    const expected = 'AB:'.repeat(31) + 'AB';
    expect(loadConfig({ ...base, UNIFI_TLS_FINGERPRINT: hex.toUpperCase() }).console.tls).toEqual({
      fingerprint: expected,
    });
    expect(loadConfig({ ...base, UNIFI_TLS_FINGERPRINT: expected.toLowerCase() }).console.tls).toEqual({
      fingerprint: expected,
    });
  });

  it.each(['abcd', 'zz'.repeat(32), 'ab'.repeat(31)])('rejects fingerprint %s', (fp) => {
    expect(() => loadConfig({ ...base, UNIFI_TLS_FINGERPRINT: fp })).toThrow(
      new ConfigError('UNIFI_TLS_FINGERPRINT must be a SHA-256 fingerprint (64 hex digits)'),
    );
  });

  it('insecure wins and drops the fingerprint', () => {
    expect(loadConfig({ ...base, UNIFI_TLS_INSECURE: 'true' }).console.tls).toEqual({ insecure: true });
    const noFp = { UNIFI_URL: base.UNIFI_URL, UNIFI_API_KEY: base.UNIFI_API_KEY };
    expect(loadConfig({ ...noFp, UNIFI_TLS_INSECURE: 'true' }).console.tls).toEqual({ insecure: true });
  });

  it('reads the optional Site Manager key', () => {
    expect(loadConfig({ ...base, UNIFI_SITE_MANAGER_API_KEY: ' sm ' }).siteManagerApiKey).toBe('sm');
  });

  it('defaults protected networks to pi-cluster and parses a list', () => {
    expect(loadConfig({ ...base }).protectedNetworks).toEqual(['pi-cluster']);
    expect(loadConfig({ ...base, UNIFI_MCP_PROTECTED_NETWORKS: 'pi-cluster, IoT' }).protectedNetworks).toEqual([
      'pi-cluster',
      'IoT',
    ]);
  });

  it.each(['', '   ', ' , ,'])('an empty protected-networks value (%j) is an error, not "gateway only"', (v) => {
    expect(() => loadConfig({ ...base, UNIFI_MCP_PROTECTED_NETWORKS: v })).toThrow(
      new ConfigError(
        'UNIFI_MCP_PROTECTED_NETWORKS is empty; set network names, or "none" to protect only the gateway',
      ),
    );
  });

  it.each(['none', 'NONE', ' None '])('"%s" protects only the gateway, explicitly', (v) => {
    expect(loadConfig({ ...base, UNIFI_MCP_PROTECTED_NETWORKS: v }).protectedNetworks).toEqual([]);
  });

  it('describes the protected networks for the startup log, warning when there are none', () => {
    expect(protectedNetworksLog(['pi-cluster', 'IoT'])).toBe('unifi-mcp: protected networks: pi-cluster, IoT');
    expect(protectedNetworksLog([])).toBe('unifi-mcp: WARNING: protected networks: none (gateway only)');
  });

  it.each(['true', '1', 'TRUE', 'True'])('read-only is on for %s', (v) => {
    expect(loadConfig({ ...base, UNIFI_MCP_READ_ONLY: v }).readOnly).toBe(true);
  });

  it.each(['false', '0', 'FALSE'])('read-only is off for %s', (v) => {
    expect(loadConfig({ ...base, UNIFI_MCP_READ_ONLY: v }).readOnly).toBe(false);
  });

  it('rejects a read-only value it does not understand', () => {
    expect(() => loadConfig({ ...base, UNIFI_MCP_READ_ONLY: 'maybe' })).toThrow(ConfigError);
  });

  it('rejects an unknown transport', () => {
    expect(() => loadConfig({ ...base, UNIFI_MCP_TRANSPORT: 'grpc' })).toThrow(/must be one of stdio, http, both/);
  });

  it('requires UNIFI_MCP_TOKEN for the http and both transports', () => {
    expect(() => loadConfig({ ...base, UNIFI_MCP_TRANSPORT: 'http' })).toThrow(/UNIFI_MCP_TOKEN is required/);
    expect(() => loadConfig({ ...base, UNIFI_MCP_TRANSPORT: 'both' })).toThrow(/UNIFI_MCP_TOKEN is required/);
  });

  it('accepts http with a token and a custom port', () => {
    const config = loadConfig({
      ...base,
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_MCP_TOKEN: 'client-secret',
      UNIFI_MCP_PORT: '8080',
    });
    expect(config).toMatchObject({ transport: 'http', token: 'client-secret', port: 8080 });
  });

  it.each(['0', '65536', 'abc', '3000.5'])('rejects port %s', (port) => {
    expect(() => loadConfig({ ...base, UNIFI_MCP_PORT: port })).toThrow(/UNIFI_MCP_PORT/);
  });
});
