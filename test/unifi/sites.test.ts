import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createSiteResolver } from '../../src/unifi/sites.js';
import { liveFixture } from '../fixtures/live.js';
import { OFFICIAL, SITE_ID, failure, testClient, useServer } from './helpers.js';

const server = useServer();
const DEFAULT = { id: SITE_ID, ref: 'default', name: 'Default' };

function serveSites(body: unknown = liveFixture('official-sites')) {
  let calls = 0;
  server.use(
    http.get(`${OFFICIAL}/sites`, () => {
      calls++;
      return HttpResponse.json(body as never);
    }),
  );
  return () => calls;
}

describe('SiteResolver', () => {
  it('with no argument gives the only site', async () => {
    serveSites();
    expect(await createSiteResolver(testClient()).resolve()).toEqual(DEFAULT);
  });

  it('finds the site by name, ref or id, ignoring case on the names', async () => {
    serveSites();
    const sites = createSiteResolver(testClient());
    for (const wanted of ['Default', 'default', 'DEFAULT', SITE_ID]) {
      expect(await sites.resolve(wanted)).toEqual(DEFAULT);
    }
  });

  it('lists the sites when the name is unknown', async () => {
    serveSites();
    const error = await createSiteResolver(testClient())
      .resolve('nope')
      .catch((e: unknown) => e);
    expect((error as Error).message).toBe(
      'No site "nope"; the sites on this console are: Default (default)',
    );
  });

  it('asks which site when there are several and none was named', async () => {
    serveSites({
      offset: 0,
      limit: 200,
      count: 2,
      totalCount: 2,
      data: [
        { id: SITE_ID, internalReference: 'default', name: 'Default' },
        { id: 'b', internalReference: 'cabin', name: 'Cabin' },
      ],
    });
    const sites = createSiteResolver(testClient());
    await expect(sites.resolve()).rejects.toThrow(
      'This console has 2 sites; pick one of: Default (default), Cabin (cabin)',
    );
    expect(await sites.resolve('cabin')).toEqual({ id: 'b', ref: 'cabin', name: 'Cabin' });
  });

  it('asks the console once, and again after a failure', async () => {
    const calls = serveSites();
    const sites = createSiteResolver(testClient());
    await sites.resolve();
    await sites.resolve('Default');
    expect(calls()).toBe(1);

    server.use(
      http.get(`${OFFICIAL}/sites`, () => HttpResponse.text('down', { status: 500 }), {
        once: true,
      }),
    );
    const flaky = createSiteResolver(testClient());
    await expect(flaky.resolve()).rejects.toThrow(/500/);
    server.use(
      http.get(`${OFFICIAL}/sites`, () =>
        HttpResponse.json(liveFixture('official-sites') as never),
      ),
    );
    expect(await flaky.resolve()).toEqual(DEFAULT);
  });

  it('reports a site list without its fields as a changed endpoint', async () => {
    serveSites({
      offset: 0,
      limit: 200,
      count: 1,
      totalCount: 1,
      data: [{ id: SITE_ID, name: 'Default' }],
    });
    const error = await failure(createSiteResolver(testClient()).resolve());
    expect(error.kind).toBe('endpoint-changed');
  });
});
