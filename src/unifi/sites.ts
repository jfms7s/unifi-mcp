import type { UnifiHttpClient } from '../http/client.js';
import { UnifiApiError } from '../http/errors.js';
import { officialPage, siteSchema } from './schemas.js';

export interface Site {
  id: string;
  /** Legacy `internalReference`, the `default` in `/s/default/…`. */
  ref: string;
  name: string;
}

export interface SiteResolver {
  /** By name, id or ref (name and ref ignore case); no argument means the only site. */
  resolve(site?: string): Promise<Site>;
  /** Every site on the console. */
  list(): Promise<Site[]>;
}

const SITE_PAGE_SIZE = 200;

export function createSiteResolver(client: UnifiHttpClient): SiteResolver {
  let cached: Promise<Site[]> | undefined;

  async function load(): Promise<Site[]> {
    const path = '/v1/sites';
    const schema = officialPage(siteSchema);
    const sites: Site[] = [];
    for (;;) {
      const raw = await client.request('official', 'GET', path, {
        query: { offset: sites.length, limit: SITE_PAGE_SIZE },
      });
      const parsed = schema.safeParse(raw);
      if (!parsed.success) {
        throw new UnifiApiError({
          kind: 'endpoint-changed',
          method: 'GET',
          path,
          detail: 'the response no longer has the fields unifi-mcp reads',
        });
      }
      sites.push(
        ...parsed.data.data.map((s) => ({ id: s.id, ref: s.internalReference, name: s.name })),
      );
      if (parsed.data.data.length === 0 || sites.length >= parsed.data.totalCount) return sites;
    }
  }

  function sites(): Promise<Site[]> {
    // A failed load must not stick: the next call tries again.
    cached ??= load().catch((error: unknown) => {
      cached = undefined;
      throw error;
    });
    return cached;
  }

  const list = (all: Site[]) => all.map((s) => `${s.name} (${s.ref})`).join(', ');

  return {
    list: () => sites(),
    async resolve(wanted) {
      const all = await sites();
      if (wanted === undefined || wanted === '') {
        if (all.length === 1) return all[0] as Site;
        throw new Error(`This console has ${all.length} sites; pick one of: ${list(all)}`);
      }
      const lower = wanted.toLowerCase();
      const found = all.find(
        (s) => s.id === wanted || s.name.toLowerCase() === lower || s.ref.toLowerCase() === lower,
      );
      if (!found)
        throw new Error(`No site "${wanted}"; the sites on this console are: ${list(all)}`);
      return found;
    },
  };
}
