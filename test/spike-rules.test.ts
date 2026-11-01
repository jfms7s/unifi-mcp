import { describe, expect, it } from 'vitest';
import {
  isSafeTarget,
  isVerifiedUnblocked,
  parseIpv4,
  pickClient,
  withNetwork,
} from '../scripts/spike-rules.js';
import type { Station } from '../src/unifi/legacy.js';

const light = (over: Partial<Station> = {}): Station => ({
  mac: 'aa:bb:cc:00:00:01',
  is_wired: false,
  ip: '192.168.11.150',
  hostname: 'Nanoleaf Indoor Lights',
  oui: 'Nanoleaf',
  network: 'IoT',
  tx_bytes: 100,
  rx_bytes: 100,
  ...over,
});
const ok = (s: Station) => pickClient(withNetwork([s], new Map())) !== undefined;

describe('spike client choice', () => {
  it('accepts an idle wireless light on IoT', () => {
    expect(ok(light())).toBe(true);
  });
  it('rejects a client with no address', () => {
    expect(ok(light({ ip: undefined }))).toBe(false);
    expect(ok(light({ ip: '' }))).toBe(false);
    expect(ok(light({ ip: 'not-an-ip' }))).toBe(false);
  });
  it('rejects anything inside 192.168.0.0/24', () => {
    expect(ok(light({ ip: '192.168.0.45' }))).toBe(false);
  });
  it('does not mistake 192.168.0x-like prefixes for the cluster subnet', () => {
    expect(ok(light({ ip: '192.168.11.150' }))).toBe(true);
    expect(parseIpv4('192.168.0.1')).toEqual([192, 168, 0, 1]);
    expect(parseIpv4('192.168.0.1.5')).toBeUndefined();
  });
  it('rejects the desktop', () => {
    expect(ok(light({ ip: '192.168.10.10' }))).toBe(false);
  });
  it('rejects pi-cluster by network name even when flagged as guest', () => {
    expect(ok(light({ network: 'pi-cluster', is_guest: true }))).toBe(false);
  });
  it('accepts a guest on another network but not a non-IoT non-guest', () => {
    expect(ok(light({ network: 'Guest', is_guest: true }))).toBe(true);
    expect(ok(light({ network: 'Default' }))).toBe(false);
  });
  it('resolves the network name from network_id', () => {
    const c = withNetwork(
      [light({ network: undefined, network_id: 'n1' })],
      new Map([['n1', 'pi-cluster']]),
    );
    expect(isSafeTarget(c[0]!)).toBe(false);
  });
  it('rejects wired, busy, blocked, non-light and safety-named clients', () => {
    expect(ok(light({ is_wired: true }))).toBe(false);
    expect(ok(light({ tx_bytes: 9_000_000 }))).toBe(false);
    expect(ok(light({ blocked: true }))).toBe(false);
    expect(ok(light({ hostname: 'HS110', oui: 'Tp-Link' }))).toBe(false);
    expect(ok(light({ name: 'Heater light' }))).toBe(false);
  });
});

describe('spike unblock verification', () => {
  it('only a definite blocked:false counts as unblocked', () => {
    expect(isVerifiedUnblocked(false)).toBe(true);
    expect(isVerifiedUnblocked(true)).toBe(false);
    expect(isVerifiedUnblocked(undefined)).toBe(false);
  });
});
