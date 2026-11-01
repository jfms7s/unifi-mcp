import { z } from 'zod';
import {
  ZBF_DISABLED,
  isZbfDisabled,
  type Api,
  type HttpMethod,
  type RequestOptions,
  type UnifiHttpClient,
} from '../../src/http/client.js';
import { UnifiApiError } from '../../src/http/errors.js';
import type { ToolDefinition } from '../../src/mcp/types.js';
import { createLegacyApi } from '../../src/unifi/legacy.js';
import { createOfficialApi } from '../../src/unifi/official.js';
import type { ReadDeps } from '../../src/unifi/read-tools.js';
import { createSiteManagerApi } from '../../src/unifi/sitemanager.js';
import { createSiteResolver } from '../../src/unifi/sites.js';
import { createSyslogApi } from '../../src/unifi/syslog.js';
import { liveFixture } from '../fixtures/live.js';

/** The newest entry in the captured log, 2026-11-01. Tests treat it as "now". */
export const FIXTURE_NOW = 1_793_532_462_018;

interface RawEntry {
  id: string;
  timestamp: number;
  [key: string]: unknown;
}

let logCache: RawEntry[] | undefined;

/** The captured system log, newest first (6,045 entries over seven pages). */
export function liveLog(): RawEntry[] {
  logCache ??= Array.from(
    { length: 7 },
    (_, i) => (liveFixture(`v2-system-log-all-page-${i}`) as { data: RawEntry[] }).data,
  ).flat();
  return logCache;
}

/** `count` copies of a log entry, one per second back from FIXTURE_NOW, each with its own id. */
export function syntheticLog(count: number, template: Partial<RawEntry> = {}): RawEntry[] {
  const base = liveLog().find((e) => e.severity === 'HIGH') as RawEntry;
  return Array.from({ length: count }, (_, i) => ({
    ...base,
    ...template,
    id: `synthetic-${i}`,
    timestamp: FIXTURE_NOW - i * 1000,
  }));
}

/** The live fixture that answers `path` on `api`. */
export function fixtureName(api: Api, path: string): string {
  if (api === 'official') {
    const rest = path
      .replace(/^\/v1\/sites\/[^/]+\/devices\/[^/]+\//, '/v1/sites/x/devices/')
      .replace(/^\/v1\/(sites\/[^/]+\/)?/, '');
    return `official-${(rest || 'sites').replace(/\/$/, '').replace(/\//g, '-')}`;
  }
  if (api === 'legacy') return `legacy-${path.replace(/^\/s\/[^/]+\//, '').replace(/[/.]/g, '-')}`;
  if (api === 'sitemanager') {
    return path.startsWith('/v1/isp-metrics/') ? 'sitemanager-isp-metrics-1h' : 'sitemanager-hosts';
  }
  throw new Error(`no fixture for ${api} ${path}`);
}

export interface FakeConsole extends UnifiHttpClient {
  /** `METHOD path` for every request, in order. */
  calls: string[];
}

/**
 * A console that answers from the live fixtures. The system log honours the
 * posted range and paging, so a 24 h window really is 24 h of the capture.
 */
export function fakeConsole(opts: { log?: RawEntry[] } = {}): FakeConsole {
  const log = opts.log ?? liveLog();
  const calls: string[] = [];

  return {
    calls,
    async request<T>(api: Api, method: HttpMethod, path: string, o: RequestOptions = {}) {
      calls.push(`${method} ${path}`);
      if (api === 'v2') {
        const body = o.body as {
          timestampFrom: number;
          timestampTo: number;
          pageNumber: number;
          pageSize: number;
        };
        const inRange = log.filter(
          (e) => e.timestamp >= body.timestampFrom && e.timestamp <= body.timestampTo,
        );
        const start = body.pageNumber * body.pageSize;
        return {
          total_element_count: inRange.length,
          page_number: body.pageNumber,
          data: inRange.slice(start, start + body.pageSize),
        } as T;
      }
      const fixture = liveFixture(fixtureName(api, path)) as { status?: number; body?: unknown };
      // A captured error response ({ status, body }) fails the way the real client does.
      if (typeof fixture.status === 'number' && isZbfDisabled(fixture.status, fixture.body)) {
        throw new UnifiApiError({
          kind: 'zbf-disabled',
          method,
          path,
          status: fixture.status,
          detail: ZBF_DISABLED,
        });
      }
      return fixture as T;
    },
  };
}

export function readDeps(
  opts: { log?: RawEntry[]; sitemanager?: boolean; now?: number } = {},
): ReadDeps & { console: FakeConsole } {
  const console_ = fakeConsole({ log: opts.log });
  const now = opts.now ?? FIXTURE_NOW;
  return {
    console: console_,
    official: createOfficialApi(console_),
    legacy: createLegacyApi(console_),
    syslog: createSyslogApi(console_),
    sitemanager: opts.sitemanager === false ? undefined : createSiteManagerApi(console_),
    sites: createSiteResolver(console_),
    now: () => now,
  };
}

/** Calls a tool the way the MCP server does: arguments parsed (defaults applied, unknown keys stripped) first. */
export function caller(tools: ToolDefinition[]) {
  return async (name: string, args: Record<string, unknown> = {}): Promise<unknown> => {
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`no tool named ${name}`);
    return tool.handler(z.object(tool.inputSchema).parse(args));
  };
}
