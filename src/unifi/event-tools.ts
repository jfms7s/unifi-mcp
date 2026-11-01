import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { limitInput, parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import { hasText } from './lookup.js';
import { EVENT_CEILING, READ, coverageNote, severityRank, type ReadDeps } from './read-common.js';
import { SEVERITIES } from './schemas.js';
import { compact, cut, iso, renderMessage } from './shape.js';
import type { SyslogEntry } from './syslog.js';

/** A scan that stopped at the ceiling is never presented as the whole range. */
function scanWarning(truncatedAt: number | undefined) {
  if (truncatedAt === undefined) return {};
  return {
    scan: {
      truncatedAt: iso(truncatedAt),
      note: coverageNote(truncatedAt),
    },
  };
}

const textMatches = (params: SyslogEntry['parameters'], keyPattern: RegExp, query: string) =>
  Object.entries(params).some(
    ([key, p]) => keyPattern.test(key) && (hasText(p.name, query) || hasText(p.id, query)),
  );

export function createEventTools(deps: ReadDeps): ToolDefinition[] {
  const { syslog, sites } = deps;
  const now = deps.now ?? Date.now;

  return [
    defineTool({
      name: 'unifi_events',
      description:
        'Search the console event log, newest first, messages rendered as the UI shows them. Filter by category (e.g. SECURITY), minSeverity, since/until (default last 24 h), device, client (name, IP or MAC, matched against the entry parameters) and text. Reads up to 20000 entries; if the range is longer it says how far back it got.',
      inputSchema: {
        site: siteInput,
        category: z.string().min(1).optional().describe('Event category, e.g. SECURITY, AUDIT, VPN'),
        minSeverity: z.enum(SEVERITIES).optional().describe('Lowest severity to return'),
        since: sinceInput,
        until: untilInput,
        device: z.string().min(1).optional().describe('Device name or MAC in the event'),
        client: z.string().min(1).optional().describe('Client name, IP or MAC in the event'),
        text: z.string().min(1).optional().describe('Text to find in the rendered message or title'),
        limit: limitInput(100, 1000),
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        const range = parseRange(a.since, a.until, '24h', now());
        const category = a.category?.toUpperCase();
        const min = a.minSeverity === undefined ? 0 : severityRank(a.minSeverity);
        const found = await syslog.scan(site.ref, {
          ...range,
          ceiling: EVENT_CEILING,
          filter: (e) =>
            (category === undefined || e.category === category) &&
            severityRank(e.severity) >= min &&
            (a.device === undefined || textMatches(e.parameters, /^(?!CONSOLE).*DEVICE/, a.device)) &&
            (a.client === undefined || textMatches(e.parameters, /CLIENT|_IP$/, a.client)) &&
            (a.text === undefined || hasText(renderMessage(e), a.text) || hasText(e.title, a.text)),
        });
        const { rows, truncated } = cut(found.entries, a.limit);
        return compact({
          site: site.name,
          range: { from: iso(range.from), to: iso(range.to) },
          total: found.entries.length,
          events: rows.map((e) => ({
            time: iso(e.timestamp),
            severity: e.severity,
            category: e.category,
            key: e.key,
            message: renderMessage(e),
          })),
          truncated,
          ...scanWarning(found.truncatedAt),
        });
      },
    }),
  ];
}
