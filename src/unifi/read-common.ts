import type { LegacyApi } from './legacy.js';
import type { OfficialApi } from './official.js';
import type { AcceptedFinding } from './posture.js';
import { SEVERITIES } from './schemas.js';
import type { SiteManagerApi } from './sitemanager.js';
import type { SiteResolver } from './sites.js';
import type { SyslogApi, SyslogEntry } from './syslog.js';

export interface ReadDeps {
  official: OfficialApi;
  legacy: LegacyApi;
  syslog: SyslogApi;
  /** Present only when a Site Manager key is configured. */
  sitemanager?: SiteManagerApi;
  sites: SiteResolver;
  /** Milliseconds since the epoch; injectable so tests can pin "now". */
  now?: () => number;
  /** Posture findings the owner accepted (UNIFI_MCP_ACCEPTED_FINDINGS). */
  acceptedFindings?: readonly AcceptedFinding[];
}

export const READ = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/** Entries read from the system log before a scan gives up and says how far it got. */
export const EVENT_CEILING = 20_000;

export const DAY_MS = 86_400_000;

export const severityRank = (s: SyslogEntry['severity']): number => SEVERITIES.indexOf(s);

/** What a scan that stopped at the ceiling tells the reader, never a partial range passed off as whole. */
export const coverageNote = (truncatedAt: number): string =>
  `stopped at ${EVENT_CEILING} events, range only covered back to ${new Date(truncatedAt).toISOString()}`;
