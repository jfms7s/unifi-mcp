import type { UnifiHttpClient } from '../http/client.js';
import { createEndpointGuard, type EndpointGuard } from './endpoint-guard.js';
import { syslogPageSchema } from './schemas.js';

export interface SyslogEntry {
  id: string;
  timestamp: number;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
  key: string;
  title: string;
  messageTemplate: string;
  parameters: Record<string, { id?: string; name?: string }>;
}

export interface SyslogApi {
  /** One page, newest first. `page` is zero-based. */
  page(
    ref: string,
    q: { from: number; to: number; page: number; size: number },
  ): Promise<{ total: number; entries: SyslogEntry[] }>;
  /**
   * Pages newest first until the range is covered or `ceiling` entries have been
   * read. `truncatedAt` is the timestamp of the oldest entry reached (or `to`,
   * if none was) and is set only when entries older than that, inside the
   * range, were left unread: at the ceiling, or when the console's paging
   * stops short of its own `total` (a capped pageSize, an ignored pageNumber).
   */
  scan(
    ref: string,
    q: { from: number; to: number; ceiling: number; filter?: (e: SyslogEntry) => boolean },
  ): Promise<{ entries: SyslogEntry[]; truncatedAt?: number }>;
}

const SCAN_PAGE_SIZE = 1000;

export function createSyslogApi(client: UnifiHttpClient, guard?: EndpointGuard): SyslogApi {
  const g = guard ?? createEndpointGuard(client);

  async function page(
    ref: string,
    q: { from: number; to: number; page: number; size: number },
  ): Promise<{ total: number; entries: SyslogEntry[] }> {
    const body = await g.call({
      api: 'v2',
      ref,
      method: 'POST',
      endpoint: 'system-log/all',
      body: {
        timestampFrom: q.from,
        timestampTo: q.to,
        pageNumber: q.page,
        pageSize: q.size,
      },
      schema: syslogPageSchema,
    });
    return {
      total: body.total_element_count,
      entries: body.data.map(({ title_raw, message_raw, ...entry }) => ({
        ...entry,
        title: title_raw,
        messageTemplate: message_raw,
      })),
    };
  }

  async function scan(
    ref: string,
    q: { from: number; to: number; ceiling: number; filter?: (e: SyslogEntry) => boolean },
  ): Promise<{ entries: SyslogEntry[]; truncatedAt?: number }> {
    const seen = new Set<string>();
    const kept: SyslogEntry[] = [];
    let read = 0;
    let oldest: number | undefined;
    const truncated = () => ({ entries: kept, truncatedAt: oldest ?? q.to });
    for (let pageNumber = 0; ; pageNumber++) {
      const { total, entries } = await page(ref, {
        from: q.from,
        to: q.to,
        page: pageNumber,
        size: SCAN_PAGE_SIZE,
      });
      let fresh = 0;
      for (const entry of entries) {
        // Entries logged while paging shift later pages; a repeat is not a new event.
        if (seen.has(entry.id)) continue;
        if (read >= q.ceiling) return truncated();
        seen.add(entry.id);
        read++;
        fresh++;
        oldest = entry.timestamp;
        if (!q.filter || q.filter(entry)) kept.push(entry);
      }
      // A page that brings nothing new before `total` is reached means the
      // console ignored pageNumber; paging on would only repeat it.
      if (fresh === 0 && read < total) return truncated();
      if (entries.length < SCAN_PAGE_SIZE) {
        // A short page is the end only if it reaches `total`; short of that the
        // console capped pageSize, and what is left of the range went unread.
        const reached = pageNumber * SCAN_PAGE_SIZE + entries.length >= total;
        return reached ? { entries: kept } : truncated();
      }
      if ((pageNumber + 1) * SCAN_PAGE_SIZE >= total) return { entries: kept };
      if (read >= q.ceiling) return truncated();
    }
  }

  return { page, scan };
}
