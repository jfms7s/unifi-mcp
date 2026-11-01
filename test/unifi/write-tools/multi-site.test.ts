import { HttpResponse, http } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';
import { buildTools } from '../../../src/tools.js';
import { liveFixture } from '../../fixtures/live.js';
import { caller } from '../fixtures.js';
import { BASE, testConfig, useServer, viaMsw } from '../helpers.js';
import { LEGACY_SITE, fakeWriteConsole } from './harness.js';

const server = useServer();

const BRANCH_ID = '00000000-0000-4000-8000-0000000000b2';

/** A fixture list with the pi-cluster network taken out. */
function withoutPiCluster(name: string): unknown {
  const page = structuredClone(liveFixture(name)) as { data: Array<{ name: string }> };
  page.data = page.data.filter((n) => n.name !== 'pi-cluster');
  return page;
}

/**
 * The captured site plus a second one, Branch, that answers from the same
 * fixtures except that it has no pi-cluster network: the same client is then
 * protected on Default and not on Branch.
 */
const setup = () =>
  fakeWriteConsole(server, {
    extraSites: [
      {
        id: BRANCH_ID,
        ref: 'branch',
        name: 'Branch',
        fixtures: {
          'official-networks': withoutPiCluster('official-networks'),
          'legacy-rest-networkconf': withoutPiCluster('legacy-rest-networkconf'),
        },
      },
    ],
  });

describe('writes on a console with two sites', () => {
  it('a write on site B is checked against B\'s scope, not the default site\'s', async () => {
    const { call, writes } = setup();
    // client-22 is on pi-cluster at Default; Branch has no pi-cluster.
    expect(await call('unifi_block_client', { site: 'Branch', client: 'client-22' })).toEqual({
      changed: 'blocked',
      client: 'client-22',
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: '/proxy/network/api/s/branch/cmd/stamgr',
        body: { cmd: 'block-sta', mac: expect.any(String) as string },
      },
    ]);
  });

  it('the same write on the default site still needs confirm', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_block_client', { site: 'Default', client: 'client-22' })) as {
      warning?: string;
      requires?: string;
    };
    expect(out.requires).toBe('confirm: true');
    expect(out.warning).toMatch(/client-22 .* is on pi-cluster/);
    expect(writes).toEqual([]);
    expect(LEGACY_SITE).toBe('/proxy/network/api/s/default');
  });

  it('site B still protects its gateway', async () => {
    const { call, writes } = setup();
    const out = (await call('unifi_restart_device', { site: 'Branch', device: 'Gateway CGU' })) as {
      warning?: string;
    };
    expect(out.warning).toMatch(/gateway/);
    expect(writes).toEqual([]);
  });

  it('without a site, a write names the sites to pick from', async () => {
    const { call, writes } = setup();
    await expect(call('unifi_block_client', { client: 'client-22' })).rejects.toThrow(
      /This console has 2 sites; pick one of: Default \(default\), Branch \(branch\)/,
    );
    expect(writes).toEqual([]);
  });
});

/**
 * The production wiring: buildTools' lazyScope over loadProtectedScope, not
 * the harness's per-call scope. The harness only serves the console.
 */
describe('writes on two sites through buildTools', () => {
  afterEach(() => server.events.removeAllListeners());
  const production = () => {
    const console = setup();
    const tools = buildTools(testConfig({ protectedNetworks: ['pi-cluster'] }), { fetch: viaMsw });
    return { ...console, call: caller(tools) };
  };

  /** rest/networkconf GETs per site ref while the test runs. */
  function networkReads() {
    const reads: Record<string, number> = {};
    server.events.on('request:start', ({ request }) => {
      const m = /\/api\/s\/([^/]+)\/rest\/networkconf$/.exec(new URL(request.url).pathname);
      if (request.method === 'GET' && m) reads[m[1]!] = (reads[m[1]!] ?? 0) + 1;
    });
    return reads;
  }

  it('keeps a scope per site: Branch is easy, Default needs confirm, each loaded once', async () => {
    const { call, writes } = production();
    const branch = { site: 'Branch', client: 'client-22' };
    expect(await call('unifi_block_client', branch)).toEqual({ changed: 'blocked', client: 'client-22' });
    const preview = (await call('unifi_block_client', { site: 'Default', client: 'client-22' })) as {
      requires?: string;
      warning?: string;
    };
    expect(preview.requires).toBe('confirm: true');
    expect(preview.warning).toMatch(/client-22 .* is on pi-cluster/);
    expect(writes.map((w) => w.path)).toEqual(['/proxy/network/api/s/branch/cmd/stamgr']);

    // Cached per site: a second write on each site loads no scope again.
    const reads = networkReads();
    const before = { ...reads };
    await call('unifi_block_client', branch);
    await call('unifi_block_client', { site: 'Default', client: 'client-22' });
    const scopeLoads = (ref: string) => (reads[ref] ?? 0) - (before[ref] ?? 0);
    // Each call still reads networkconf for its own client lookup, but no more.
    expect([scopeLoads('branch'), scopeLoads('default')]).toEqual([1, 1]);
  });

  it("two sites' scopes load at the same time, and each write gets its own", async () => {
    const { call, writes } = production();
    // Hold every networkconf read until both sites have asked, so both loads are in flight at once.
    const seen = new Set<string>();
    let release!: () => void;
    const both = new Promise<void>((r) => (release = r));
    let together = false;
    server.use(
      http.get(`${BASE}/proxy/network/api/s/:ref/rest/networkconf`, async ({ params }) => {
        const ref = String(params.ref);
        seen.add(ref);
        if (seen.size === 2) {
          together = true;
          release();
        }
        await Promise.race([both, new Promise((r) => setTimeout(r, 2000))]);
        const body =
          ref === 'branch'
            ? withoutPiCluster('legacy-rest-networkconf')
            : liveFixture('legacy-rest-networkconf');
        return HttpResponse.json(body as never);
      }),
    );
    const [branch, home] = (await Promise.all([
      call('unifi_block_client', { site: 'Branch', client: 'client-22' }),
      call('unifi_block_client', { site: 'Default', client: 'client-22' }),
    ])) as Array<Record<string, unknown>>;
    expect(together).toBe(true);
    expect(branch).toEqual({ changed: 'blocked', client: 'client-22' });
    expect(home!.requires).toBe('confirm: true');
    expect(writes.map((w) => w.path)).toEqual(['/proxy/network/api/s/branch/cmd/stamgr']);
  });
});
