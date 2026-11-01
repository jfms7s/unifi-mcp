import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createLegacyApi } from '../../src/unifi/legacy.js';
import {
  LEGACY,
  failure,
  legacyNotFound,
  sysinfoHandler,
  testClient,
  useServer,
} from './helpers.js';

const server = useServer();
const legacy = () => createLegacyApi(testClient());
const MAC = 'aa:bb:cc:dd:ee:ff';

describe('legacy cmd', () => {
  it('cmd posts the exact body', async () => {
    let body: unknown;
    let method = '';
    server.use(
      http.post(`${LEGACY}/cmd/stamgr`, async ({ request }) => {
        body = await request.json();
        method = request.method;
        return HttpResponse.json({ meta: { rc: 'ok' }, data: [] });
      }),
    );
    await legacy().cmd('default', 'stamgr', { cmd: 'block-sta', mac: MAC });
    expect(method).toBe('POST');
    expect(body).toEqual({ cmd: 'block-sta', mac: MAC });
  });

  it('posts devmgr commands to the devmgr manager', async () => {
    let body: unknown;
    server.use(
      http.post(`${LEGACY}/cmd/devmgr`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ meta: { rc: 'ok' }, data: [] });
      }),
    );
    await legacy().cmd('default', 'devmgr', { cmd: 'set-locate', mac: MAC });
    expect(body).toEqual({ cmd: 'set-locate', mac: MAC });
  });

  it('an rc:error body is a status error carrying the console message', async () => {
    server.use(
      http.post(`${LEGACY}/cmd/stamgr`, () =>
        HttpResponse.json({ meta: { rc: 'error', msg: 'api.err.UnknownDevice' }, data: [] }),
      ),
    );
    const error = await failure(
      legacy().cmd('default', 'stamgr', { cmd: 'unblock-sta', mac: MAC }),
    );
    expect(error.kind).toBe('status');
    expect(error.detail).toBe('api.err.UnknownDevice');
  });

  it('api.err.NotFound is a changed endpoint', async () => {
    server.use(http.post(`${LEGACY}/cmd/stamgr`, legacyNotFound), sysinfoHandler());
    const error = await failure(legacy().cmd('default', 'stamgr', { cmd: 'kick-sta', mac: MAC }));
    expect(error.kind).toBe('endpoint-changed');
  });
});
