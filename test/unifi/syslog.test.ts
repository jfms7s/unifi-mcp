import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createSyslogApi, type SyslogApi } from '../../src/unifi/syslog.js';
import { liveFixture } from '../fixtures/live.js';
import { V2, failure, htmlNotFound, sysinfoHandler, testClient, useServer } from './helpers.js';

const server = useServer();
const syslog = (): SyslogApi => createSyslogApi(testClient());
const REF = 'default';
const Q = { from: 0, to: 2_000_000_000_000 };

interface RawPage {
  total_element_count: number;
  data: Record<string, unknown>[];
}

function serveLog(onRequest?: (body: { pageNumber: number; pageSize: number }) => void) {
  server.use(
    http.post(`${V2}/system-log/all`, async ({ request }) => {
      const body = (await request.json()) as { pageNumber: number; pageSize: number };
      onRequest?.(body);
      return HttpResponse.json(liveFixture(`v2-system-log-all-page-${body.pageNumber}`) as never);
    }),
  );
}

describe('syslog.page', () => {
  it('posts the range and page in the console field names and reads total_element_count', async () => {
    let sent: unknown;
    server.use(
      http.post(`${V2}/system-log/all`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(liveFixture('v2-system-log-all-page-0') as never);
      }),
    );
    const { total, entries } = await syslog().page(REF, {
      from: 100,
      to: 200,
      page: 0,
      size: 1000,
    });
    expect(sent).toEqual({ timestampFrom: 100, timestampTo: 200, pageNumber: 0, pageSize: 1000 });
    expect(total).toBe(6045);
    expect(entries).toHaveLength(1000);
  });

  it('maps the raw title and message to title and messageTemplate', async () => {
    serveLog();
    const { entries } = await syslog().page(REF, { ...Q, page: 0, size: 1000 });
    const threat = entries.find((e) => e.key === 'THREAT_DETECTED_KNOWN_DESTINATION_CLIENT');
    expect(threat).toMatchObject({
      category: 'SECURITY',
      severity: 'HIGH',
      title: 'Threat Detected',
      messageTemplate:
        'A network intrusion attempt from {SRC_IP} to {DST_CLIENT} has been detected.',
    });
    expect(threat?.parameters.DST_CLIENT).toMatchObject({ id: '02:00:00:00:00:1a' });
    expect(threat).not.toHaveProperty('title_raw');
  });
});

describe('syslog.scan', () => {
  it('stops at the ceiling and says where the oldest entry it read was', async () => {
    const requested: number[] = [];
    serveLog((b) => requested.push(b.pageNumber));
    const result = await syslog().scan(REF, { ...Q, ceiling: 1500 });
    const page1 = liveFixture('v2-system-log-all-page-1') as RawPage;
    expect(result.entries).toHaveLength(1500);
    expect(result.truncatedAt).toBe(page1.data[499]!.timestamp);
    expect(result.entries.at(-1)!.timestamp).toBe(result.truncatedAt);
    expect(requested).toEqual([0, 1]);
  });

  it('reads all 6,045 entries, newest first, when the ceiling is higher', async () => {
    serveLog();
    const result = await syslog().scan(REF, { ...Q, ceiling: 20_000 });
    expect(result.entries).toHaveLength(6045);
    expect(result.truncatedAt).toBeUndefined();
    const times = result.entries.map((e) => e.timestamp);
    expect(times).toEqual([...times].sort((a, b) => b - a));
  });

  it('is not truncated when the ceiling equals the number of entries', async () => {
    serveLog();
    const result = await syslog().scan(REF, { ...Q, ceiling: 6045 });
    expect(result.entries).toHaveLength(6045);
    expect(result.truncatedAt).toBeUndefined();
  });

  it('filters what it keeps while the ceiling counts what it read', async () => {
    serveLog();
    const result = await syslog().scan(REF, {
      ...Q,
      ceiling: 20_000,
      filter: (e) => e.category === 'SECURITY',
    });
    expect(result.entries.length).toBeGreaterThan(0);
    expect(result.entries.length).toBeLessThan(6045);
    expect(result.entries.every((e) => e.category === 'SECURITY')).toBe(true);

    const capped = await syslog().scan(REF, { ...Q, ceiling: 1000, filter: () => false });
    expect(capped.entries).toEqual([]);
    expect(capped.truncatedAt).toBeDefined();
  });

  it('drops an entry that shows up on two pages', async () => {
    const first = liveFixture('v2-system-log-all-page-0') as RawPage;
    const second = structuredClone(liveFixture('v2-system-log-all-page-1')) as RawPage;
    second.data[0] = first.data[999]!; // a new event pushed it onto the next page
    server.use(
      http.post(`${V2}/system-log/all`, async ({ request }) => {
        const { pageNumber } = (await request.json()) as { pageNumber: number };
        const page = pageNumber === 0 ? first : pageNumber === 1 ? second : { ...second, data: [] };
        return HttpResponse.json({ ...page, total_element_count: 2000 } as never);
      }),
    );
    const result = await syslog().scan(REF, { ...Q, ceiling: 20_000 });
    expect(result.entries).toHaveLength(1999);
    expect(new Set(result.entries.map((e) => e.id)).size).toBe(1999);
  });
});

describe('syslog reports a changed endpoint', () => {
  const expected =
    "the console's legacy endpoint system-log/all changed or is gone (Network 10.6.109); update unifi-mcp";
  const call = () => syslog().page(REF, { ...Q, page: 0, size: 1000 });

  it('HTML 404 page', async () => {
    server.use(http.post(`${V2}/system-log/all`, htmlNotFound), sysinfoHandler());
    const error = await failure(call());
    expect(error.kind).toBe('endpoint-changed');
    expect(error.message).toBe(expected);
  });

  it('legacy-style not-found body', async () => {
    server.use(
      http.post(`${V2}/system-log/all`, () =>
        HttpResponse.json({ meta: { rc: 'error', msg: 'api.err.NotFound' }, data: [] }),
      ),
      sysinfoHandler(),
    );
    expect((await failure(call())).message).toBe(expected);
  });

  it('JSON 404', async () => {
    server.use(
      http.post(`${V2}/system-log/all`, () =>
        HttpResponse.json({ error: 'nope' }, { status: 404 }),
      ),
      sysinfoHandler(),
    );
    expect((await failure(call())).message).toBe(expected);
  });

  for (const field of ['total_element_count', 'data']) {
    it(`${field} missing`, async () => {
      const page = structuredClone(liveFixture('v2-system-log-all-page-6')) as Record<
        string,
        unknown
      >;
      delete page[field];
      server.use(
        http.post(`${V2}/system-log/all`, () => HttpResponse.json(page as never)),
        sysinfoHandler(),
      );
      expect((await failure(call())).message).toBe(expected);
    });
  }

  it('an entry without its message template', async () => {
    const page = structuredClone(liveFixture('v2-system-log-all-page-6')) as RawPage;
    delete page.data[0]!.message_raw;
    server.use(
      http.post(`${V2}/system-log/all`, () => HttpResponse.json(page as never)),
      sysinfoHandler(),
    );
    expect((await failure(call())).message).toBe(expected);
  });
});
