import { describe, expect, it, vi } from 'vitest';
import { bearerAuth, isAuthorized } from '../../src/mcp/auth.js';

describe('isAuthorized', () => {
  it('accepts the exact bearer token', () => {
    expect(isAuthorized('Bearer s3cret', 's3cret')).toBe(true);
  });

  it('rejects a wrong token of the same length', () => {
    expect(isAuthorized('Bearer s3cres', 's3cret')).toBe(false);
  });

  it('rejects a token of a different length without throwing', () => {
    expect(isAuthorized('Bearer short', 'a-much-longer-secret')).toBe(false);
  });

  it('rejects a missing header', () => {
    expect(isAuthorized(undefined, 's3cret')).toBe(false);
  });

  it('rejects a header without the Bearer scheme', () => {
    expect(isAuthorized('s3cret', 's3cret')).toBe(false);
    expect(isAuthorized('Basic s3cret', 's3cret')).toBe(false);
  });

  it('accepts a case-insensitive scheme', () => {
    expect(isAuthorized('bearer s3cret', 's3cret')).toBe(true);
  });
});

describe('bearerAuth', () => {
  function invoke(header: string | undefined) {
    const middleware = bearerAuth('s3cret');
    const json = vi.fn();
    const status = vi.fn().mockReturnValue({ json });
    const next = vi.fn();
    middleware({ headers: { authorization: header } } as never, { status } as never, next);
    return { status, json, next };
  }

  it('calls next for a valid token', () => {
    const { next, status } = invoke('Bearer s3cret');
    expect(next).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
  });

  it('responds 401 for an invalid token and does not call next', () => {
    const { next, status, json } = invoke('Bearer wrong');
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalled();
  });

  it('never includes the expected token in the response body', () => {
    const { json } = invoke(undefined);
    expect(JSON.stringify(json.mock.calls)).not.toContain('s3cret');
  });
});
