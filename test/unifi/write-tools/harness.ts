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
import { caller, fixtureName, orderingFor } from '../fixtures.js';
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
  /** Only present when the write had a query string. */
  query?: Record<string, string>;
}

export interface ConsoleOptions {
  links?: LinkSpec[];
  /** Replaces a fixture's body, by fixture name (e.g. `legacy-rest-user`). */
  fixtures?: Record<string, unknown>;
  /** What an official write answers (default: an empty 200); a function sees the write. */
  officialReply?: unknown;
  /** Firewall zone and policy reads answer the ZBF-not-configured 400, as before ZBF was on. */
  zbfOff?: boolean;
  /**
   * More sites besides the captured one. Each answers from the same fixtures,
   * except its own `fixtures` overrides, matched by its id (official paths)
   * or ref (legacy paths).
   */
  extraSites?: Array<{ id: string; ref: string; name: string; fixtures?: Record<string, unknown> }>;
}

/** The extra site a path is for, by official site id or legacy ref. */
function siteOf(path: string, opts: ConsoleOptions) {
  return opts.extraSites?.find(
    (s) => path.includes(`/sites/${s.id}/`) || path.includes(`/api/s/${s.ref}/`),
  );
}

/** The captured sites list with the extra sites appended. */
function sitesWith(extra: NonNullable<ConsoleOptions['extraSites']>): unknown {
  const page = structuredClone(liveFixture('official-sites')) as {
    data: unknown[];
    count: number;
    totalCount: number;
  };
  page.data.push(...extra.map((s) => ({ id: s.id, internalReference: s.ref, name: s.name })));
  page.count = page.data.length;
  page.totalCount = page.data.length;
  return page;
}

/** `official-networks-<id>`, `official-firewall-policies-<id>`...: one object of a list. */
const DETAIL =
  /^(official-(?:networks|wifi-broadcasts|firewall-policies|firewall-zones|acl-rules|dns-policies|traffic-matching-lists))-([0-9a-z-]{1,36})$/;
const ZBF_PATH = /\/firewall\/(zones|policies)(\/|$)/;

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
      if (opts.zbfOff && ZBF_PATH.test(path)) {
        const zbf = liveFixture('official-firewall-zbf-disabled') as {
          status: number;
          body: unknown;
        };
        return HttpResponse.json(zbf.body as never, { status: zbf.status });
      }
      const name = fixtureName(api, path.slice(prefix.length));
      const site = siteOf(path, opts);
      if (site?.fixtures?.[name] !== undefined)
        return HttpResponse.json(site.fixtures[name] as never);
      if (name === 'official-sites' && opts.extraSites) {
        return HttpResponse.json(sitesWith(opts.extraSites) as never);
      }
      if (name === 'official-firewall-policies-ordering' && opts.fixtures?.[name] === undefined) {
        const query = Object.fromEntries(new URL(request.url).searchParams);
        return HttpResponse.json(orderingFor(query) as never);
      }
      const detail = DETAIL.exec(name);
      if (detail && opts.fixtures?.[name] === undefined) {
        // A detail GET answers with that row of the list fixture, as the console would.
        const [, list = '', id] = detail;
        const page = (opts.fixtures?.[list] ?? liveFixture(list)) as {
          data: Array<{ id: string }>;
        };
        const row = page.data.find((r) => r.id === id);
        return row
          ? HttpResponse.json(row as never)
          : HttpResponse.json({ statusCode: 404, code: 'api.err.NotFound' }, { status: 404 });
      }
      const body =
        opts.fixtures?.[name] ??
        (name === 'legacy-stat-device' ? statDevice(opts.links ?? LIVE_LINKS) : liveFixture(name));
      return HttpResponse.json(body as never);
    }),
    ...[http.post, http.put, http.delete].map((verb) =>
      verb(`${BASE}/proxy/network/*`, async ({ request }) => {
        const path = new URL(request.url).pathname;
        const text = await request.text();
        const url = new URL(request.url);
        const write: Write = {
          method: request.method,
          path,
          body: text ? (JSON.parse(text) as unknown) : undefined,
          ...(url.search ? { query: Object.fromEntries(url.searchParams) } : {}),
        };
        onWrite(write);
        if (path.startsWith('/proxy/network/api/')) {
          return HttpResponse.json({ meta: { rc: 'ok' }, data: [] });
        }
        const reply =
          typeof opts.officialReply === 'function'
            ? (opts.officialReply as (w: Write) => unknown)(write)
            : opts.officialReply;
        if (reply instanceof Response) return reply;
        return reply === undefined
          ? new HttpResponse(null, { status: 200 })
          : HttpResponse.json(reply as never);
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
    scope: (site) => loadProtectedScope(['pi-cluster'], base, site),
    consoleHost: new URL(BASE).hostname,
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
