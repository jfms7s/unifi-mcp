import type { z } from 'zod';
import type { UnifiHttpClient } from '../http/client.js';
import { UnifiApiError } from '../http/errors.js';
import {
  hostSchema,
  ispMetricsSchema,
  siteManagerEnvelope,
  type Host,
  type IspMetrics,
} from './schemas.js';

export type { Host, IspMetrics };

export interface SiteManagerApi {
  hosts(): Promise<Host[]>;
  /** `range` is ISO 8601; without it Site Manager's default window applies. */
  ispMetrics(interval: '5m' | '1h', range?: { begin: string; end: string }): Promise<IspMetrics[]>;
}

/** A pager that never ends would loop forever; no account has this many consoles. */
const MAX_PAGES = 20;

export function createSiteManagerApi(client: UnifiHttpClient): SiteManagerApi {
  async function list<T extends z.ZodType>(
    path: string,
    item: T,
    query: Record<string, string | undefined> = {},
  ): Promise<z.infer<T>[]> {
    const schema = siteManagerEnvelope(item);
    const all: z.infer<T>[] = [];
    let nextToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const raw = await client.request('sitemanager', 'GET', path, {
        query: { ...query, nextToken },
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
      all.push(...parsed.data.data);
      nextToken = parsed.data.nextToken;
      if (!nextToken) break;
    }
    return all;
  }

  return {
    hosts: () => list('/v1/hosts', hostSchema),
    ispMetrics: (interval, range) =>
      list(`/v1/isp-metrics/${interval}`, ispMetricsSchema, {
        beginTimestamp: range?.begin,
        endTimestamp: range?.end,
      }),
  };
}
