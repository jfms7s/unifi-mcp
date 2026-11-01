import { z } from 'zod';

export const siteInput = z
  .string()
  .min(1)
  .optional()
  .describe('Site name, id or reference; optional while the console has a single site');

export function limitInput(defaultN: number, maxN: number) {
  return z
    .number()
    .int()
    .min(1)
    .max(maxN)
    .default(defaultN)
    .describe(`Rows to return (default ${defaultN}, at most ${maxN})`);
}

const TIME_HELP =
  'an ISO 8601 timestamp (2026-10-31T08:00:00Z) or a span back from now such as 90m, 24h, 7d or 2w';

export const sinceInput = z.string().min(1).optional().describe(`Start of the range: ${TIME_HELP}`);

export const untilInput = z
  .string()
  .min(1)
  .optional()
  .describe(`End of the range (default now): ${TIME_HELP}`);

/** Same strictness as a missing flag: only `true` confirms, `false` and strings are refused. */
export const confirmInput = z
  .literal(true)
  .optional()
  .describe('Must be true to carry out a guarded change; without it the tool only previews it');

const UNIT_MS = { m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 } as const;
const RELATIVE = /^([1-9]\d{0,5})([mhdw])$/;

/** Milliseconds since the epoch for an ISO timestamp, or `now` minus a relative span. */
export function parseTime(value: string, now: number = Date.now()): number {
  const relative = RELATIVE.exec(value.trim());
  if (relative) return now - Number(relative[1]) * UNIT_MS[relative[2] as keyof typeof UNIT_MS];
  const absolute = /^\d{4}-\d{2}-\d{2}/.test(value) ? Date.parse(value) : Number.NaN;
  if (Number.isNaN(absolute)) {
    throw new Error(`"${value}" is not a time; use ${TIME_HELP}`);
  }
  return absolute;
}

export function parseRange(
  since: string | undefined,
  until: string | undefined,
  defaultSpan: string,
  now: number = Date.now(),
): { from: number; to: number } {
  const to = until === undefined ? now : parseTime(until, now);
  const from = parseTime(since ?? defaultSpan, now);
  if (from >= to)
    throw new Error('The range starts at or after its end; since must be before until');
  return { from, to };
}
