import { describe, expect, it } from 'vitest';
import { UnifiApiError } from '../../../src/http/errors.js';
import { diff, hidingSecrets, merge } from '../../../src/unifi/write-tools/objects.js';

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
