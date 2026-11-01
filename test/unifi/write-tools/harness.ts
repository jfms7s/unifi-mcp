// A console behind msw for the write tools: every GET answers from the live
// fixtures (stat/device from the hand-made topology), and every POST or DELETE
// is recorded with its exact path and body, so a test can assert precisely
// what was sent, or that nothing was.
import { HttpResponse, http } from 'msw';
import type { SetupServer } from 'msw/node';
import { vi } from 'vitest';
import { loadProtectedScope } from '../../../src/unifi/guard.js';
import { createLegacyApi } from '../../../src/unifi/legacy.js';
import { createOfficialApi } from '../../../src/unifi/official.js';
import { createSiteResolver } from '../../../src/unifi/sites.js';
import { createSyslogApi } from '../../../src/unifi/syslog.js';
import { createWriteTools, type WriteDeps } from '../../../src/unifi/write-tools/index.js';
import { liveFixture } from '../../fixtures/live.js';
import { caller, fixtureName } from '../fixtures.js';
import { BASE, SITE_ID, testClient } from '../helpers.js';
import { LIVE_LINKS, statDevice, type LinkSpec } from '../topology.js';

export { SITE_ID };
/** Paths as the console sees them, so assertions read like the API docs. */
export const OFFICIAL_SITE = `/proxy/network/integration/v1/sites/${SITE_ID}`;
export const LEGACY_SITE = '/proxy/network/api/s/default';

export interface Write {
  method: string;
  path: string;
  body: unknown;
}

export interface ConsoleOptions {
  links?: LinkSpec[];
  /** Replaces a fixture's body, by fixture name (e.g. `legacy-rest-user`). */
  fixtures?: Record<string, unknown>;
  /** What an official write answers (default: an empty 200). */
  officialReply?: unknown;
}

const PREFIXES = [
  ['/proxy/network/integration', 'official'],
  ['/proxy/network/api', 'legacy'],
] as const;

export function fakeWriteConsole(server: SetupServer, opts: ConsoleOptions = {}) {
  const writes: Write[] = [];
  const onWrite = vi.fn((w: Write) => void writes.push(w));

  server.use(
    http.get(`${BASE}/proxy/network/*`, ({ request }) => {
      const path = new URL(request.url).pathname;
      const [prefix, api] = PREFIXES.find(([p]) => path.startsWith(`${p}/`)) ?? [];
      if (prefix === undefined || api === undefined) throw new Error(`no fixture for ${path}`);
      const name = fixtureName(api, path.slice(prefix.length));
      const body =
        opts.fixtures?.[name] ??
        (name === 'legacy-stat-device' ? statDevice(opts.links ?? LIVE_LINKS) : liveFixture(name));
      return HttpResponse.json(body as never);
    }),
    ...[http.post, http.delete].map((verb) =>
      verb(`${BASE}/proxy/network/*`, async ({ request }) => {
        const path = new URL(request.url).pathname;
        const text = await request.text();
        onWrite({
          method: request.method,
          path,
          body: text ? (JSON.parse(text) as unknown) : undefined,
        });
        if (path.startsWith('/proxy/network/api/')) {
          return HttpResponse.json({ meta: { rc: 'ok' }, data: [] });
        }
        return opts.officialReply === undefined
          ? new HttpResponse(null, { status: 200 })
          : HttpResponse.json(opts.officialReply as never);
      }),
    ),
  );

  const client = testClient();
  const base = {
    official: createOfficialApi(client),
    legacy: createLegacyApi(client),
    syslog: createSyslogApi(client),
    sites: createSiteResolver(client),
  };
  const deps: WriteDeps = {
    ...base,
    scope: async () => loadProtectedScope(['pi-cluster'], base, await base.sites.resolve()),
  };
  const tools = createWriteTools(deps);
  return { writes, onWrite, tools, call: caller(tools) };
}

/** rest/user with one more client, offline (not in stat/sta). */
export function withOfflineUser(row: Record<string, unknown>): unknown {
  const users = structuredClone(liveFixture('legacy-rest-user')) as { data: unknown[] };
  users.data.push(row);
  return users;
}

/** official clients with one client's access type replaced. */
export function withAccess(name: string, type: string): unknown {
  const page = structuredClone(liveFixture('official-clients')) as {
    data: Array<{ name: string; access?: { type: string } }>;
  };
  const row = page.data.find((c) => c.name === name);
  if (!row) throw new Error(`no official client named ${name}`);
  row.access = { type };
  return page;
}
