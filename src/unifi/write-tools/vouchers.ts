import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import type { Voucher } from '../official.js';
import { compact } from '../shape.js';
import { write, type WriteDeps } from './common.js';

/** How many matching vouchers a bulk-delete preview lists. */
const PREVIEW_ROWS = 50;

/** A string literal in the official filter syntax: single quotes, a quote doubled. */
const quoted = (s: string) => `'${s.replace(/'/g, "''")}'`;

/** The official filter for a bulk delete; ids are validated GUIDs, so they go in bare. */
export function voucherFilter(opts: { ids?: string[]; name?: string; expired?: boolean }): string {
  const parts = [
    opts.ids && `id.in(${opts.ids.join(', ')})`,
    opts.name !== undefined && `name.eq(${quoted(opts.name)})`,
    opts.expired !== undefined && `expired.eq(${opts.expired})`,
  ].filter((p): p is string => typeof p === 'string');
  if (parts.length === 0) {
    throw new Error(
      'Give at least one of ids, name or expired: a bulk delete never runs without a filter',
    );
  }
  return parts.length === 1 ? parts[0]! : `and(${parts.join(', ')})`;
}

const createdRow = (v: Voucher) =>
  compact({
    id: v.id,
    name: v.name,
    code: v.code,
    timeLimitMinutes: v.timeLimitMinutes,
    authorizedGuestLimit: v.authorizedGuestLimit,
    dataUsageLimitMBytes: v.dataUsageLimitMBytes,
    expiresAt: v.expiresAt,
  });

const listedRow = (v: Voucher) =>
  compact({ id: v.id, name: v.name, expired: v.expired, createdAt: v.createdAt });

export function createVoucherWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [
    defineTool({
      name: 'unifi_create_vouchers',
      description:
        'Generate hotspot (guest portal) vouchers (official POST /hotspot/vouchers) and return their codes.',
      inputSchema: {
        site: siteInput,
        name: z.string().min(1).describe('Voucher name (a note shared by the batch)'),
        timeLimitMinutes: z
          .number()
          .int()
          .min(1)
          .max(1_000_000)
          .describe('How long a voucher grants access once used'),
        count: z.number().int().min(1).max(1000).optional().describe('How many (default 1)'),
        authorizedGuestLimit: z
          .number()
          .int()
          .min(1)
          .optional()
          .describe('Guests per voucher (absent: unlimited)'),
        dataUsageLimitMBytes: z.number().int().min(1).max(1_048_576).optional(),
        rxRateLimitKbps: z.number().int().min(2).max(100_000).optional(),
        txRateLimitKbps: z.number().int().min(2).max(100_000).optional(),
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, ...request }) => {
        const site = await deps.sites.resolve(wanted);
        const body = compact(request);
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'create vouchers', ...body }),
            run: async () => ({
              changed: 'created',
              vouchers: (await deps.official.createVouchers(site.id, body)).map(createdRow),
            }),
          },
          await deps.scope(),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_delete_voucher',
      description: 'Delete one hotspot voucher by its id (official DELETE).',
      inputSchema: { site: siteInput, voucherId: z.guid().describe('Voucher id') },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, voucherId }) => {
        const site = await deps.sites.resolve(wanted);
        return guarded(
          {
            level: 'easy',
            preview: async () => ({ would: 'delete voucher', voucherId }),
            run: async () => ({
              changed: 'deleted',
              vouchersDeleted: await deps.official.deleteVoucher(site.id, voucherId),
            }),
          },
          await deps.scope(),
          [],
        );
      },
    }),
    defineTool({
      name: 'unifi_delete_vouchers',
      description:
        'Delete every hotspot voucher a filter matches (official bulk DELETE): by ids, exact name and/or expired; several criteria must all match. Always needs confirm: true; without it the tool lists what would go.',
      inputSchema: {
        site: siteInput,
        ids: z.array(z.guid()).min(1).optional().describe('Voucher ids'),
        name: z.string().min(1).optional().describe('Exact voucher name'),
        expired: z.boolean().optional().describe('true: expired vouchers; false: unexpired ones'),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, confirm, ...criteria }) => {
        const filter = voucherFilter(criteria);
        const site = await deps.sites.resolve(wanted);
        return guarded(
          {
            level: 'confirm',
            confirm,
            preview: async () => {
              const matching = await deps.official.listVouchers(site.id, filter);
              return compact({
                would: 'delete vouchers',
                filter,
                matching: matching.length,
                vouchers: matching.slice(0, PREVIEW_ROWS).map(listedRow),
                truncated:
                  matching.length > PREVIEW_ROWS
                    ? { shown: PREVIEW_ROWS, total: matching.length }
                    : undefined,
              });
            },
            run: async () => ({
              changed: 'deleted',
              vouchersDeleted: await deps.official.deleteVouchers(site.id, filter),
            }),
          },
          await deps.scope(),
          [],
        );
      },
    }),
  ];
}
