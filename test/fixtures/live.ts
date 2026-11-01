import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const LIVE_DIR = resolve(import.meta.dirname, 'live');

/**
 * A scrubbed response captured from the live console by
 * scripts/capture-fixtures.ts, by file name without `.json`, e.g.
 * `liveFixture('legacy-stat-sta')` or `liveFixture('v2-system-log-all-page-0')`.
 */
export function liveFixture(name: string): unknown {
  if (!/^[a-z0-9.-]+$/.test(name)) throw new Error(`not a fixture name: ${name}`);
  return JSON.parse(readFileSync(resolve(LIVE_DIR, `${name}.json`), 'utf8')) as unknown;
}
