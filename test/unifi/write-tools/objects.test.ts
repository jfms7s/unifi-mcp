import { describe, expect, it } from 'vitest';
import { UnifiApiError } from '../../../src/http/errors.js';
import { diff, hidingSecrets, merge, redact, secretsIn } from '../../../src/unifi/write-tools/objects.js';

describe('diff', () => {
  it('a secret that changes says "changed", one that goes away says "removed"', () => {
    expect(diff({ s: { passphrase: 'a' } }, { s: { passphrase: 'b' } })).toEqual({
      's.passphrase': 'changed',
    });
    expect(diff({ s: { type: 'X', passphrase: 'a' } }, { s: { type: 'OPEN' } })).toEqual({
      's.type': { before: 'X', after: 'OPEN' },
      's.passphrase': 'removed',
    });
    expect(diff({ s: { passphrase: 'a' } }, { s: { passphrase: null } })).toEqual({
      's.passphrase': 'removed',
    });
  });
});

describe('secret keys beyond passphrases', () => {
  it('redacts psk, key and *Key string values, and finds them as secrets', () => {
    const value = { psk: 'p1', key: 'k1', wpaKey: 'k2', x_passphrase: 'k3', name: 'lan', keyCount: 2 };
    expect(redact(value)).toEqual({
      psk: '<redacted>',
      key: '<redacted>',
      wpaKey: '<redacted>',
      x_passphrase: '<redacted>',
      name: 'lan',
      keyCount: 2,
    });
    expect(secretsIn(value).sort()).toEqual(['k1', 'k2', 'k3', 'p1']);
  });

  it('a PSK entry that changes shows as "changed" in the diff, never its value', () => {
    expect(diff({ s: { key: 'old' } }, { s: { key: 'new' } })).toEqual({ 's.key': 'changed' });
    expect(diff({ psks: [{ psk: 'a' }] }, { psks: [{ psk: 'b' }] })).toEqual({ psks: 'changed' });
  });
});

describe('secret keys: no false positives', () => {
  it('leaves booleans, numbers and non-secret *pass*/*Key/*Mode fields as they are', () => {
    const value = {
      bypassEnabled: true,
      bypassList: 'a,b',
      sortKey: 'name',
      pskMode: 'WPA2',
      pskEnabled: false,
      keyCount: 2,
      passphraseLength: 12,
      passwordPolicy: { minLength: 8 },
      secretCount: 3,
      key: 7,
    };
    expect(redact(value)).toEqual(value);
    expect(secretsIn(value)).toEqual([]);
    expect(diff({ s: { sortKey: 'a', pskMode: 'WPA2' } }, { s: { sortKey: 'b', pskMode: 'WPA3' } })).toEqual({
      's.sortKey': { before: 'a', after: 'b' },
      's.pskMode': { before: 'WPA2', after: 'WPA3' },
    });
  });

  it('redacts string values under secret keys and their suffixes', () => {
    const value = {
      password: 'p1',
      adminPassword: 'p2',
      radiusSecret: 's1',
      presharedKey: 'k1',
      wpaPsk: 'k2',
      secret: 's2',
    };
    expect(Object.values(redact(value) as object).every((v) => v === '<redacted>')).toBe(true);
    expect(secretsIn(value).sort()).toEqual(['k1', 'k2', 'p1', 'p2', 's1', 's2']);
  });

  it('redacts nested PSK entries (presharedKeys[].passphrase and .key)', () => {
    const value = {
      presharedKeys: [
        { name: 'guest', passphrase: 'pp1', vlan: 10 },
        { name: 'iot', key: 'kk1', enabled: true },
      ],
    };
    expect(redact(value)).toEqual({
      presharedKeys: [
        { name: 'guest', passphrase: '<redacted>', vlan: 10 },
        { name: 'iot', key: '<redacted>', enabled: true },
      ],
    });
    expect(secretsIn(value).sort()).toEqual(['kk1', 'pp1']);
    const after = {
      presharedKeys: [
        { name: 'guest', passphrase: 'pp2', vlan: 10 },
        { name: 'iot', key: 'kk1', enabled: true },
      ],
    };
    expect(diff(value, after)).toEqual({ presharedKeys: 'changed' });
    expect(JSON.stringify(diff(value, { presharedKeys: [] }))).not.toMatch(/pp1|kk1/);
  });
});

describe('merge', () => {
  it('replaces a nested object whose mode changes, merges one whose mode stays', () => {
    const base = { d: { mode: 'SERVER', range: 1, lease: 2 } };
    expect(merge(base, { d: { mode: 'RELAY', servers: ['x'] } })).toEqual({
      d: { mode: 'RELAY', servers: ['x'] },
    });
    expect(merge(base, { d: { mode: 'SERVER', lease: 3 } })).toEqual({
      d: { mode: 'SERVER', range: 1, lease: 3 },
    });
  });
});

describe('hidingSecrets', () => {
  const failing = (error: unknown) => () => Promise.reject(error);

  it('with a secret in play, withholds the detail of a console error and keeps kind and status', async () => {
    const original = new UnifiApiError({
      kind: 'status',
      method: 'PUT',
      path: '/x',
      status: 400,
      detail: 'api.err.InvalidPassphrase: abc"de is weak',
    });
    const err = (await hidingSecrets(['abc"de'], failing(original)).catch(
      (e) => e,
    )) as UnifiApiError;
    expect(err).toBeInstanceOf(UnifiApiError);
    expect(err.kind).toBe('status');
    expect(err.status).toBe(400);
    expect(err.message).toBe(
      'UniFi returned 400 for PUT /x: the console rejected the change (HTTP 400, api.err.InvalidPassphrase); details withheld because the request carried a passphrase',
    );
  });

  it('withholds even when the secret is not found verbatim (escaped or cut)', async () => {
    const original = new UnifiApiError({
      kind: 'status',
      method: 'PUT',
      path: '/x',
      status: 400,
      detail: 'value abc\\"d...',
    });
    const err = (await hidingSecrets(['abc"def'], failing(original)).catch((e) => e)) as Error;
    expect(err.message).not.toContain('abc');
  });

  it('a plain error is replaced too', async () => {
    const err = (await hidingSecrets(['s3cret-pass'], failing(new Error('boom s3cret'))).catch(
      (e) => e,
    )) as Error;
    expect(err).toBeInstanceOf(Error);
    expect(err.message).not.toContain('s3cret');
    expect(err.message).toMatch(/details withheld because the request carried a passphrase/);
  });

  it('with no secret in play the error passes through untouched', async () => {
    const original = new Error('boom');
    await expect(hidingSecrets([], failing(original))).rejects.toBe(original);
  });
});
