import { describe, expect, it } from 'vitest';
import { UnifiApiError, describeError, hasStatus } from '../../src/http/errors.js';

describe('UnifiApiError', () => {
  it('formats an answered request with status, method and path', () => {
    const error = new UnifiApiError({
      kind: 'status',
      method: 'GET',
      path: '/v1/sites',
      status: 404,
      detail: 'not found',
    });
    expect(error.message).toBe('UniFi returned 404 for GET /v1/sites: not found');
    expect(error.name).toBe('UnifiApiError');
    expect(error.kind).toBe('status');
    expect(error.status).toBe(404);
    expect(error.detail).toBe('not found');
  });

  it('names the base URL when the request never arrived', () => {
    const error = new UnifiApiError({
      kind: 'unreachable',
      method: 'GET',
      path: '/v1/sites',
      detail: 'connect ECONNREFUSED 192.168.10.1:443',
      baseUrl: 'https://192.168.10.1',
    });
    expect(error.message).toBe(
      'Cannot reach UniFi at https://192.168.10.1 for GET /v1/sites: connect ECONNREFUSED 192.168.10.1:443',
    );
  });

  it('never puts credentials from the base URL into the message', () => {
    const error = new UnifiApiError({
      kind: 'unreachable',
      method: 'GET',
      path: '/v1/sites',
      detail: 'getaddrinfo ENOTFOUND c.test',
      baseUrl: 'https://user:hunter2@c.test',
    });
    expect(error.message).not.toContain('hunter2');
    expect(error.message).toContain('https://c.test');
  });

  it('says what timed out', () => {
    const error = new UnifiApiError({
      kind: 'timeout',
      method: 'GET',
      path: '/v1/sites',
      detail: 'no answer from the console after 15 s',
    });
    expect(error.message).toBe(
      'UniFi timed out on GET /v1/sites: no answer from the console after 15 s',
    );
  });

  it('names a changed endpoint', () => {
    const error = new UnifiApiError({
      kind: 'endpoint-changed',
      method: 'GET',
      path: '/s/default/stat/sta',
      status: 200,
      detail: 'response was not valid JSON',
    });
    expect(error.message).toBe(
      'UniFi endpoint changed for GET /s/default/stat/sta: response was not valid JSON',
    );
  });

  it('uses the detail alone for certificate and ZBF errors, which stand on their own', () => {
    const cert = new UnifiApiError({
      kind: 'certificate-changed',
      method: 'GET',
      path: '/v1/info',
      detail: 'console certificate changed: expected AA, got BB',
    });
    expect(cert.message).toBe('console certificate changed: expected AA, got BB');
    const zbf = new UnifiApiError({
      kind: 'zbf-disabled',
      method: 'GET',
      path: '/x',
      status: 400,
      detail: 'ZBF off',
    });
    expect(zbf.message).toBe('ZBF off');
  });
});

describe('describeError', () => {
  it('uses an Error message and stringifies anything else', () => {
    expect(describeError(new Error('boom'))).toBe('boom');
    expect(describeError('plain')).toBe('plain');
  });
});

describe('hasStatus', () => {
  it('matches only a UnifiApiError with that status', () => {
    const error = new UnifiApiError({
      kind: 'status',
      method: 'GET',
      path: '/x',
      status: 500,
      detail: 'x',
    });
    expect(hasStatus(error, 500)).toBe(true);
    expect(hasStatus(error, 404)).toBe(false);
    expect(hasStatus(new Error('x'), 500)).toBe(false);
  });
});

describe('UnifiApiError with a finished message', () => {
  it('uses the message verbatim and keeps the fields', () => {
    const error = new UnifiApiError({
      kind: 'endpoint-changed',
      method: 'GET',
      path: '/s/default/stat/health',
      detail: 'gone',
      message: 'update unifi-mcp',
    });
    expect(error.message).toBe('update unifi-mcp');
    expect(error.kind).toBe('endpoint-changed');
    expect(error.path).toBe('/s/default/stat/health');
  });
});
