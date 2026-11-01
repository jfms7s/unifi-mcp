import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createSiteManagerApi } from '../../src/unifi/sitemanager.js';
import { liveFixture } from '../fixtures/live.js';
import { failure, testClient, useServer } from './helpers.js';

const server = useServer();
const SM = 'https://api.ui.com/v1';
const api = (overrides: { siteManagerApiKey?: string | undefined } = {}) =>
  createSiteManagerApi(testClient(overrides));

describe('Site Manager', () => {
  it('hosts returns the console from the fixture', async () => {
    server.use(
      http.get(`${SM}/hosts`, () => HttpResponse.json(liveFixture('sitemanager-hosts') as never)),
    );
    const hosts = await api().hosts();
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({
      type: 'console',
      reportedState: { name: 'Gateway CGU', state: 'connected' },
    });
  });

  it('hosts follows nextToken', async () => {
    const page = liveFixture('sitemanager-hosts') as { data: unknown[] };
    server.use(
      http.get(`${SM}/hosts`, ({ request }) => {
        const token = new URL(request.url).searchParams.get('nextToken');
        return HttpResponse.json(
          token ? { data: page.data } : { data: page.data, nextToken: 't2' },
        );
      }),
    );
    expect(await api().hosts()).toHaveLength(2);
  });

  it('ispMetrics returns the periods and sends the range', async () => {
    let query = '';
    server.use(
      http.get(`${SM}/isp-metrics/1h`, ({ request }) => {
        query = new URL(request.url).search;
        return HttpResponse.json(liveFixture('sitemanager-isp-metrics-1h') as never);
      }),
    );
    const [metrics] = await api().ispMetrics('1h', {
      begin: '2026-10-01T00:00:00Z',
      end: '2026-10-02T00:00:00Z',
    });
    expect(metrics!.periods).toHaveLength(714);
    expect(metrics!.periods[0]!.data.wan).toMatchObject({ avgLatency: 7, uptime: 100 });
    expect(query).toContain('beginTimestamp=2026-10-01T00%3A00%3A00Z');
    expect(query).toContain('endTimestamp=');
  });

  it('a response without the periods is an endpoint change', async () => {
    server.use(
      http.get(`${SM}/isp-metrics/5m`, () => HttpResponse.json({ data: [{ metricType: '5m' }] })),
    );
    const error = await failure(api().ispMetrics('5m'));
    expect(error.kind).toBe('endpoint-changed');
  });

  it('rejects before any request when no Site Manager key is configured', async () => {
    await expect(api({ siteManagerApiKey: undefined }).hosts()).rejects.toThrow(
      /Site Manager is not configured/,
    );
  });
});
