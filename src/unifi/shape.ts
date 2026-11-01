import type { SyslogEntry } from './syslog.js';

/** Turns a log template and its parameters into the sentence the UniFi UI shows. */
export function renderMessage(entry: Pick<SyslogEntry, 'messageTemplate' | 'parameters'>): string {
  return entry.messageTemplate.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name: string) => {
    const parameter = entry.parameters[name];
    return parameter?.name || parameter?.id || `{${name}?}`;
  });
}

export function iso(ms: number | undefined): string | undefined {
  return ms === undefined ? undefined : new Date(ms).toISOString();
}

/** Seconds since the epoch (the legacy API) to an ISO string. */
export function isoFromSeconds(seconds: number | undefined): string | undefined {
  return seconds === undefined ? undefined : iso(seconds * 1000);
}

const MODEL_NAMES: Record<string, string> = {
  'UCG Ultra': 'UniFi Cloud Gateway Ultra',
  'UCG Max': 'UniFi Cloud Gateway Max',
  'UCG Fiber': 'UniFi Cloud Gateway Fiber',
  'UDM Pro': 'UniFi Dream Machine Pro',
  'UDM Pro Max': 'UniFi Dream Machine Pro Max',
  'UDM SE': 'UniFi Dream Machine SE',
  UDM: 'UniFi Dream Machine',
  'UDR': 'UniFi Dream Router',
  'UDR7': 'UniFi Dream Router 7',
};

const GATEWAY_MODEL = /^(UCG|UDM|UDR|UDW|UXG|EFG|UGW)/i;

export const isGatewayModel = (model: string): boolean => GATEWAY_MODEL.test(model);

/** The product name for a model code; an unknown code is shown as it came. */
export function modelName(model: string): string {
  return MODEL_NAMES[model] ?? model;
}

/** Drops keys whose value is undefined so rows stay compact. */
export function compact<T extends Record<string, unknown>>(row: T): T {
  return Object.fromEntries(Object.entries(row).filter(([, v]) => v !== undefined)) as T;
}

/** Cuts a list and says so; nothing is dropped without `truncated`. */
export function cut<T>(
  rows: T[],
  limit: number,
): { rows: T[]; truncated?: { shown: number; total: number } } {
  return rows.length <= limit
    ? { rows }
    : { rows: rows.slice(0, limit), truncated: { shown: limit, total: rows.length } };
}
