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
  it('leaves booleans, numbers, bypass* and the sortKey/publicKey allow-list as they are', () => {
    const value = {
      bypassEnabled: true,
      bypassList: 'a,b',
      sortKey: 'name',
      publicKey: 'wg-pub',
      pskMode: true,
      pskEnabled: false,
      keyCount: 2,
      passphraseLength: 12,
      secretCount: 3,
      key: 7,
    };
    expect(redact(value)).toEqual(value);
    expect(secretsIn(value)).toEqual([]);
    expect(diff({ s: { sortKey: 'a', pskMode: true } }, { s: { sortKey: 'b', pskMode: false } })).toEqual({
      's.sortKey': { before: 'a', after: 'b' },
      's.pskMode': { before: true, after: false },
    });
  });

  it('over-redacts a string or object under a *pass*/*psk* name, as v0.2.0 did (R22)', () => {
    const value = { pskMode: 'WPA2', passwordPolicy: { minLength: 8 } };
    expect(redact(value)).toEqual({ pskMode: '<redacted>', passwordPolicy: '<redacted>' });
    expect(diff({ pskMode: 'WPA2' }, { pskMode: 'WPA3' })).toEqual({ pskMode: 'changed' });
  });

  it('a bypass prefix does not hide a secret name after it', () => {
    expect(redact({ bypassPassword: 'bp1' })).toEqual({ bypassPassword: '<redacted>' });
    expect(secretsIn({ bypassPassword: 'bp1' })).toEqual(['bp1']);
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

  it('redacts nested secret entries (entries[].passphrase and .key)', () => {
    const value = {
      entries: [
        { name: 'guest', passphrase: 'pp1', vlan: 10 },
        { name: 'iot', key: 'kk1', enabled: true },
      ],
    };
    expect(redact(value)).toEqual({
      entries: [
        { name: 'guest', passphrase: '<redacted>', vlan: 10 },
        { name: 'iot', key: '<redacted>', enabled: true },
      ],
    });
    expect(secretsIn(value).sort()).toEqual(['kk1', 'pp1']);
    const after = {
      entries: [
        { name: 'guest', passphrase: 'pp2', vlan: 10 },
        { name: 'iot', key: 'kk1', enabled: true },
      ],
    };
    expect(diff(value, after)).toEqual({ entries: 'changed' });
    expect(JSON.stringify(diff(value, { entries: [] }))).not.toMatch(/pp1|kk1/);
  });

  it('presharedKeys (it contains sharedkey) is redacted whole, entries and all', () => {
    const value = { presharedKeys: [{ name: 'guest', passphrase: 'pp1', vlan: 10 }] };
    expect(redact(value)).toEqual({ presharedKeys: '<redacted>' });
    expect(secretsIn(value)).toContain('pp1');
    expect(diff(value, { presharedKeys: [] })).toEqual({ presharedKeys: 'changed' });
  });
});

describe('secret keys: wider coverage (r1)', () => {
  it('redacts privateKey, apiKey, *token and sharedKey strings, any case', () => {
    const value = { privateKey: 'a1', APIKEY: 'a2', authToken: 'a3', token: 'a4', radiusSharedKey: 'a5' };
    expect(Object.values(redact(value) as object).every((v) => v === '<redacted>')).toBe(true);
    expect(secretsIn(value).sort()).toEqual(['a1', 'a2', 'a3', 'a4', 'a5']);
  });

  it('redacts any x_ string, but not an x_ boolean or number', () => {
    const value = { x_iapp_key: 's1', x_whatever: 's2', x_enabled: true, x_count: 4 };
    expect(redact(value)).toEqual({
      x_iapp_key: '<redacted>',
      x_whatever: '<redacted>',
      x_enabled: true,
      x_count: 4,
    });
    expect(secretsIn(value).sort()).toEqual(['s1', 's2']);
  });

  it('an array of strings under a secret key is secret', () => {
    const value = { passphrases: ['p1'], wpaPsk: ['p2', 'p3'], names: ['lan'] };
    expect(redact({ ...value, psk: ['p4'] })).toMatchObject({ psk: '<redacted>', names: ['lan'] });
    expect(secretsIn({ psk: ['p4', 'p5'] }).sort()).toEqual(['p4', 'p5']);
    expect(diff({ psk: ['a'] }, { psk: ['b'] })).toEqual({ psk: 'changed' });
    expect(JSON.stringify(diff({ token: ['a'] }, { token: ['b', 'c'] }))).not.toMatch(/"[abc]"/);
  });

  it('an object under a secret key is redacted whole', () => {
    const value = { secret: { value: 's1', nested: { k: 's2' } }, apiKey: { id: 7, v: 's3' } };
    expect(redact(value)).toEqual({ secret: '<redacted>', apiKey: '<redacted>' });
    expect(secretsIn(value).sort()).toEqual(['s1', 's2', 's3']);
    expect(diff({ secret: { value: 'a' } }, { secret: { value: 'b' } })).toEqual({ secret: 'changed' });
    expect(diff({ secret: { value: 'a' } }, {})).toEqual({ secret: 'removed' });
  });

  it('still leaves the old false positives alone', () => {
    const value = { sortKey: 'name', pskMode: true, keyCount: 2, tokenCount: 3, pskEnabled: false, key: 7 };
    expect(redact(value)).toEqual(value);
  });
});

describe('secret keys: R22 superset of v0.2.0 (final review I1)', () => {
  it('redacts secretKey, authKey, wepKey, encryptionKey and adminPass strings', () => {
    const value = { secretKey: 'r1', authKey: 'r2', wepKey: 'r3', encryptionKey: 'r4', adminPass: 'r5' };
    expect(Object.values(redact(value) as object).every((v) => v === '<redacted>')).toBe(true);
    expect(secretsIn(value).sort()).toEqual(['r1', 'r2', 'r3', 'r4', 'r5']);
    expect(diff({ authKey: 'a' }, { authKey: 'b' })).toEqual({ authKey: 'changed' });
  });

  it('an array of objects under a secret name is redacted whole, diffed blind and searched', () => {
    const value = { psk: [{ value: 'S1' }, { value: 'S2', vlan: 4 }] };
    expect(redact(value)).toEqual({ psk: '<redacted>' });
    expect(secretsIn(value).sort()).toEqual(['S1', 'S2']);
    expect(diff(value, { psk: [{ value: 'S3' }] })).toEqual({ psk: 'changed' });
    expect(JSON.stringify(diff(value, { psk: [{ value: 'S3' }] }))).not.toMatch(/S[123]/);
  });

  it('a mixed array under a secret name is redacted whole', () => {
    const value = { token: ['S6', 7] };
    expect(redact(value)).toEqual({ token: '<redacted>' });
    expect(secretsIn(value)).toEqual(['S6']);
    expect(JSON.stringify(diff(value, { token: ['S7', 7] }))).not.toMatch(/S[67]/);
  });

  // v0.2.0 (03a4f5a) redacted any key matching /pass|secret|psk/i whatever its
  // value, and any string whose key is `key` or ends in key after a letter or `_`.
  const v020 = (key: string, value: unknown): boolean =>
    value != null && (/pass|secret|psk/i.test(key) || (/(^|[a-z_])key$/i.test(key) && typeof value === 'string'));

  const V020_REDACTED: Array<[string, unknown]> = [
    ['password', 'v1'],
    ['passphrase', 'v2'],
    ['x_passphrase', 'v3'],
    ['adminPass', 'v4'],
    ['adminPassword', 'v5'],
    ['radiusPassword', 'v6'],
    ['secret', 'v7'],
    ['radiusSecret', 'v8'],
    ['clientSecret', 'v9'],
    ['psk', 'v10'],
    ['wpaPsk', 'v11'],
    ['pskMode', 'WPA2'],
    ['passwordPolicy', { minLength: 8 }],
    ['psk', ['v12']],
    ['psk', [{ value: 'v13' }]],
    ['passphrases', ['v14', 15]],
    ['secret', { value: 'v16' }],
    ['key', 'v17'],
    ['x_key', 'v18'],
    ['wpaKey', 'v19'],
    ['wepKey', 'v20'],
    ['authKey', 'v21'],
    ['secretKey', 'v22'],
    ['encryptionKey', 'v23'],
    ['presharedKey', 'v24'],
    ['privateKey', 'v25'],
    ['apiKey', 'v26'],
    ['sharedKey', 'v27'],
    ['x_iapp_key', 'v28'],
    ['wpa_key', 'v29'],
    ['radiusSharedKey', 'v30'],
  ];

  it.each(V020_REDACTED)('%s (%j), redacted by v0.2.0, is still redacted', (key, value) => {
    expect(v020(key, value)).toBe(true);
    expect(redact({ [key]: value })).toEqual({ [key]: '<redacted>' });
    expect(redact({ outer: [{ [key]: value }] })).toEqual({ outer: [{ [key]: '<redacted>' }] });
    const strings = JSON.stringify(value).match(/v\d+|WPA2/g) ?? [];
    expect(secretsIn({ [key]: value }).sort()).toEqual([...strings].sort());
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
