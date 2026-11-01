import { describe, expect, it } from 'vitest';
import { liveFixture } from '../../fixtures/live.js';
import { useServer } from '../helpers.js';
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
