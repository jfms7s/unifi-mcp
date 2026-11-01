import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { X509Certificate } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TlsConfig, UnifiMcpConfig } from '../../src/config.js';
import { createUnifiHttpClient } from '../../src/http/client.js';
import { UnifiApiError } from '../../src/http/errors.js';

const fixture = (name: string) =>
  readFileSync(new URL(`../fixtures/tls/${name}`, import.meta.url), 'utf8');
const cert = fixture('cert.pem');
const key = fixture('key.pem');
const pinned = new X509Certificate(cert).fingerprint256;
const other = 'AA:' + 'BB:'.repeat(30) + 'CC';

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer({ key, cert }, (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ path: req.url, key: req.headers['x-api-key'] === 'console-key' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function clientWith(tls: TlsConfig, url = baseUrl) {
  const config: UnifiMcpConfig = {
    console: { baseUrl: url, apiKey: 'console-key', tls },
    readOnly: false,
    protectedNetworks: [],
    transport: 'stdio',
    port: 3000,
  };
  return createUnifiHttpClient(config);
}

describe('console TLS pinning', () => {
  it('accepts the pinned fingerprint', async () => {
    // The fixture is CN=unifi.local and the server is 127.0.0.1: only the pin is checked, never the name.
    await expect(
      clientWith({ fingerprint: pinned }).request('official', 'GET', '/v1/info'),
    ).resolves.toEqual({
      path: '/proxy/network/integration/v1/info',
      key: true,
    });
  });

  it('rejects a different fingerprint', async () => {
    const error = await clientWith({ fingerprint: other })
      .request('official', 'GET', '/v1/info')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(UnifiApiError);
    expect((error as UnifiApiError).kind).toBe('certificate-changed');
    expect((error as UnifiApiError).message).toBe(
      `console certificate changed: expected ${other}, got ${pinned}`,
    );
  });

  it('does not follow a redirect off the pinned console', async () => {
    let received: string | string[] | undefined | null = null;
    const plain = createHttpServer((req, res) => {
      received = req.headers['x-api-key'];
      res.end('{}');
    });
    await new Promise<void>((resolve) => plain.listen(0, '127.0.0.1', resolve));
    const plainOrigin = `http://127.0.0.1:${(plain.address() as AddressInfo).port}`;
    const redirecting = createServer({ key, cert }, (_req, res) => {
      res.writeHead(302, { Location: `${plainOrigin}/x?y=1` }).end();
    });
    await new Promise<void>((resolve) => redirecting.listen(0, '127.0.0.1', resolve));
    try {
      const port = (redirecting.address() as AddressInfo).port;
      const error = await clientWith({ fingerprint: pinned }, `https://127.0.0.1:${port}`)
        .request('official', 'GET', '/v1/info')
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(UnifiApiError);
      expect((error as UnifiApiError).kind).toBe('endpoint-changed');
      expect((error as UnifiApiError).detail).toBe(`unexpected redirect to ${plainOrigin}`);
      expect(received).toBeNull();
    } finally {
      redirecting.closeAllConnections();
      plain.closeAllConnections();
      await new Promise<void>((resolve) => redirecting.close(() => resolve()));
      await new Promise<void>((resolve) => plain.close(() => resolve()));
    }
  });

  it('the pinned dispatcher refuses a plain-TCP connection', async () => {
    let received = false;
    const plain = createHttpServer((_req, res) => {
      received = true;
      res.end('{}');
    });
    await new Promise<void>((resolve) => plain.listen(0, '127.0.0.1', resolve));
    try {
      const port = (plain.address() as AddressInfo).port;
      const error = await clientWith({ fingerprint: pinned }, `http://127.0.0.1:${port}`)
        .request('official', 'GET', '/v1/info')
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(UnifiApiError);
      expect((error as UnifiApiError).kind).toBe('unreachable');
      expect((error as UnifiApiError).detail).toBe(
        'refusing a plain-TCP connection to a console with a pinned certificate',
      );
      expect(received).toBe(false);
    } finally {
      plain.closeAllConnections();
      await new Promise<void>((resolve) => plain.close(() => resolve()));
    }
  });

  it('insecure accepts any cert', async () => {
    await expect(clientWith({ insecure: true }).request('legacy', 'GET', '/self')).resolves.toEqual(
      {
        path: '/proxy/network/api/self',
        key: true,
      },
    );
  });
});
