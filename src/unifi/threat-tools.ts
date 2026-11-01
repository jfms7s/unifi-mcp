import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import { EVENT_CEILING, READ, type ReadDeps } from './read-common.js';
import { summariseThreats } from './threats.js';

export function createThreatTools(deps: ReadDeps): ToolDefinition[] {
  const { syslog, legacy, sites } = deps;
  const now = deps.now ?? Date.now;

  return [
    defineTool({
      name: 'unifi_threat_summary',
      description:
        'What security issues need attention: SECURITY log entries (default last 7 days) grouped by direction and LAN side (inbound to a client, outbound from a client, firewall blocks, other keys), ranked by worst severity then count. Each group has counts by severity, first/last seen, distinct remote IPs with the top 5, and the port forwards that expose an inbound target. Groups past maxGroups are summarised as a tail, never dropped; topRemotesOverall shows one remote hitting several clients. Reads up to 20000 log entries and says how far back it got if the range was longer.',
      inputSchema: {
        site: siteInput,
        since: sinceInput,
        until: untilInput,
        maxGroups: z
          .number()
          .int()
          .min(1)
          .max(100)
          .default(15)
          .describe('Groups to list before the rest are summarised (default 15, at most 100)'),
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        const range = parseRange(a.since, a.until, '7d', now());
        const [scan, forwards, clients] = await Promise.all([
          syslog.scan(site.ref, {
            ...range,
            ceiling: EVENT_CEILING,
            filter: (e) => e.category === 'SECURITY',
          }),
          legacy.portForwards(site.ref),
          legacy.knownClients(site.ref),
        ]);
        return {
          site: site.name,
          ...summariseThreats(scan.entries, forwards, clients, {
            maxGroups: a.maxGroups,
            truncatedAt: scan.truncatedAt,
            range,
          }),
        };
      },
    }),
  ];
}
