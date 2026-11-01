import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createEndpointGuard } from '../../src/unifi/endpoint-guard.js';
import { legacyEnvelope, healthSchema } from '../../src/unifi/schemas.js';
import { LEGACY, failure, htmlNotFound, sysinfoHandler, testClient, useServer } from './helpers.js';

const server = useServer();
const call = () =>
  createEndpointGuard(testClient()).call({
    api: 'legacy',
    ref: 'default',
    method: 'GET',
    endpoint: 'stat/health',
    schema: legacyEnvelope(healthSchema),
  });

describe('endpoint guard', () => {
  it('names the endpoint and Network version when it is gone', async () => {
    server.use(http.get(`${LEGACY}/stat/health`, htmlNotFound), sysinfoHandler());
    expect((await failure(call())).message).toBe(
      "the console's legacy endpoint stat/health changed or is gone (Network 10.6.109); update unifi-mcp",
    );
  });

  it('passes an rc:error that is not NotFound through as a status error', async () => {
    server.use(
      http.get(`${LEGACY}/stat/health`, () =>
        HttpResponse.json({ meta: { rc: 'error', msg: 'api.err.NoSiteContext' }, data: [] }),
      ),
    );
    const error = await failure(call());
    expect(error.kind).toBe('status');
    expect(error.message).toContain('api.err.NoSiteContext');
  });
});
