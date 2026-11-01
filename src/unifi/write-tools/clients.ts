import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { clientRow, loadClients, type ClientRecord } from '../clients.js';
import { guarded, type Target } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import type { CmdBody, KnownClient } from '../legacy.js';
import { ambiguous, findClient } from '../lookup.js';
import type { ClientActionBody } from '../official.js';
import type { Site } from '../sites.js';
import { compact } from '../shape.js';
import { write, type WriteDeps } from './common.js';

const clientInput = z.string().min(1).describe('Client name, IP, MAC or id');

/** What a result calls the client: its name, else its IP, never a bare MAC when there is an IP. */
export const displayName = (c: ClientRecord): string =>
  c.name !== c.mac ? c.name : (c.ip ?? c.mac);

/** The guard reads only identity, address and network for a client target. */
const asKnown = (c: ClientRecord): KnownClient => ({
  id: c.id,
  mac: c.mac,
  name: c.name,
  ip: c.ip,
  networkId: c.networkId,
  blocked: c.blocked,
});

type Resolved =
  | { site: Site; record: ClientRecord; records: ClientRecord[]; officialNote?: string }
  | { candidates: ReturnType<typeof ambiguous> };

async function resolveClient(
  deps: WriteDeps,
  wanted: string | undefined,
  query: string,
): Promise<Resolved> {
  const site = await deps.sites.resolve(wanted);
  const { records, note } = await loadClients(deps, site);
  const match = findClient(records, query, { exactOnly: true });
  if ('none' in match) throw new Error(`No client matches "${query}"`);
  if ('ambiguous' in match) {
    return { candidates: ambiguous(query, match.ambiguous, clientRow, match.partial) };
  }
  return { site, record: match.found, records, officialNote: note };
}

/**
 * One guarded client change. The guard's target is built from the resolved
 * record (its MAC), never from the raw query, so a name, IP or id all reach
 * the same protected-network check.
 */
async function change(
  deps: WriteDeps,
  args: { site?: string; client: string; confirm?: true },
  opts: {
    would: string;
    /** More of what would change, for the preview. */
    detail?: Record<string, unknown>;
    /** Unguarded changes (giving access back) pass false. */
    guard: boolean;
    run: (site: Site, c: ClientRecord) => Promise<object>;
    /** `officialNote` is set when the official client list failed (see loadClients). */
    check?: (c: ClientRecord, officialNote: string | undefined) => void;
  },
): Promise<unknown> {
  const r = await resolveClient(deps, args.site, args.client);
  if ('candidates' in r) return r.candidates;
  const { site, record, records, officialNote } = r;
  opts.check?.(record, officialNote);
  const target: Target | undefined = opts.guard
    ? { kind: 'client', ipOrMac: record.mac }
    : undefined;
  return guarded(
    {
      level: 'easy',
      target,
      confirm: args.confirm,
      preview: async () =>
        compact({
          would: opts.would,
          client: displayName(record),
          ip: record.ip,
          network: record.network,
          connected: record.connected,
          ...opts.detail,
        }),
      run: () => opts.run(site, record),
    },
    await deps.scope(site),
    records.map(asKnown),
  );
}

function stamgr(deps: WriteDeps, cmd: CmdBody['cmd'], changed: string) {
  return async (site: Site, c: ClientRecord) => {
    await deps.legacy.cmd(site.ref, 'stamgr', { cmd, mac: c.mac });
    return { changed, client: displayName(c) };
  };
}

/**
 * Guest actions go by the official id, which only clients the official API
 * lists have; when that list failed, the refusal says so instead of guessing.
 */
function needsOfficial(c: ClientRecord, officialNote?: string): string {
  if (c.officialId === undefined) {
    throw new Error(
      officialNote === undefined
        ? `${displayName(c)} isn't known to the official API; it may be offline`
        : `${displayName(c)} has no official id: ${officialNote}`,
    );
  }
  return c.officialId;
}

function mustBeGuest(c: ClientRecord, officialNote?: string): void {
  needsOfficial(c, officialNote);
  if (c.access !== undefined && c.access !== 'GUEST') {
    throw new Error(
      `${displayName(c)} is not a guest client (access ${c.access}); only guests can be authorized`,
    );
  }
}

const expiresSchema = z.object({ grantedAuthorization: z.object({ expiresAt: z.string() }) });

export function createClientWriteTools(deps: WriteDeps): ToolDefinition[] {
  const base = { site: siteInput, client: clientInput, confirm: confirmInput };
  const GUARD_NOTE =
    'A client on a protected network (pi-cluster by default) needs confirm: true; without it the tool previews. An ambiguous name returns the candidates and changes nothing.';

  return [
    defineTool({
      name: 'unifi_block_client',
      description: `Block a client from the network (legacy cmd/stamgr block-sta) until it is unblocked. ${GUARD_NOTE}`,
      inputSchema: base,
      annotations: write({ destructive: true, idempotent: true }),
      handler: (args) =>
        change(deps, args, {
          would: 'block',
          guard: true,
          run: stamgr(deps, 'block-sta', 'blocked'),
        }),
    }),
    defineTool({
      name: 'unifi_unblock_client',
      description:
        'Unblock a blocked client (legacy cmd/stamgr unblock-sta). It gives access back, so it is never guarded. An ambiguous name returns the candidates and changes nothing.',
      inputSchema: base,
      annotations: write({ destructive: false, idempotent: true }),
      handler: (args) =>
        change(deps, args, {
          would: 'unblock',
          guard: false,
          run: stamgr(deps, 'unblock-sta', 'unblocked'),
        }),
    }),
    defineTool({
      name: 'unifi_reconnect_client',
      description: `Disconnect a client so it reconnects (legacy cmd/stamgr kick-sta). ${GUARD_NOTE}`,
      inputSchema: base,
      annotations: write({ destructive: false, idempotent: false }),
      handler: (args) =>
        change(deps, args, {
          would: 'reconnect',
          guard: true,
          run: stamgr(deps, 'kick-sta', 'reconnected'),
        }),
    }),
    defineTool({
      name: 'unifi_authorize_guest',
      description: `Authorize a guest client (official AUTHORIZE_GUEST_ACCESS). Replaces any active authorization and resets its counters. Limits are optional; without minutes the site's default applies. ${GUARD_NOTE}`,
      inputSchema: {
        ...base,
        minutes: z
          .number()
          .int()
          .min(1)
          .max(1_000_000)
          .optional()
          .describe('How long the guest stays authorized'),
        dataLimitMb: z
          .number()
          .int()
          .min(1)
          .max(1_048_576)
          .optional()
          .describe('Data usage limit in megabytes'),
        rxKbps: z
          .number()
          .int()
          .min(2)
          .max(100_000)
          .optional()
          .describe('Download rate limit in kbit/s'),
        txKbps: z
          .number()
          .int()
          .min(2)
          .max(100_000)
          .optional()
          .describe('Upload rate limit in kbit/s'),
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: ({ minutes, dataLimitMb, rxKbps, txKbps, ...args }) =>
        change(deps, args, {
          would: 'authorize guest',
          detail: compact({ minutes, dataLimitMb, rxKbps, txKbps }),
          guard: true,
          check: mustBeGuest,
          run: async (site, c) => {
            const body: ClientActionBody = {
              action: 'AUTHORIZE_GUEST_ACCESS',
              ...compact({
                timeLimitMinutes: minutes,
                dataUsageLimitMBytes: dataLimitMb,
                rxRateLimitKbps: rxKbps,
                txRateLimitKbps: txKbps,
              }),
            };
            const reply = await deps.official.clientAction(site.id, needsOfficial(c), body);
            // The change is made; an answer without the expiry only drops that line.
            const granted = expiresSchema.safeParse(reply);
            return compact({
              changed: 'guest authorized',
              client: displayName(c),
              expiresAt: granted.success ? granted.data.grantedAuthorization.expiresAt : undefined,
            });
          },
        }),
    }),
    defineTool({
      name: 'unifi_unauthorize_guest',
      description: `Revoke a guest client's authorization and disconnect it (official UNAUTHORIZE_GUEST_ACCESS). ${GUARD_NOTE}`,
      inputSchema: base,
      annotations: write({ destructive: false, idempotent: true }),
      handler: (args) =>
        change(deps, args, {
          would: 'unauthorize guest',
          guard: true,
          check: needsOfficial,
          run: async (site, c) => {
            await deps.official.clientAction(site.id, needsOfficial(c), {
              action: 'UNAUTHORIZE_GUEST_ACCESS',
            });
            return { changed: 'guest unauthorized', client: displayName(c) };
          },
        }),
    }),
  ];
}
