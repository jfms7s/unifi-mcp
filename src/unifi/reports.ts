/** The most points a report returns; a day of 5-minute buckets is 288. */
export const MAX_REPORT_POINTS = 200;

const isNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

function averageBucket<T extends { time: number }>(bucket: T[]): T {
  const out: Record<string, unknown> = { ...bucket[0] };
  for (const key of Object.keys(out)) {
    const values = bucket.map((p) => (p as Record<string, unknown>)[key]).filter(isNumber);
    if (values.length > 0) out[key] = values.reduce((a, b) => a + b, 0) / values.length;
  }
  // The bucket sits at the middle of the span it covers; whole milliseconds keep it a timestamp.
  out.time = Math.round(out.time as number);
  return out as T;
}

/**
 * Shrinks a time-ordered series to at most `maxPoints`. The first and last
 * points stay as they are, so the range's ends are real readings; the points
 * between are split into equal runs and each run is replaced by the average of
 * its numeric fields (a field some points lack is averaged over those that
 * have it). Other fields come from the run's first point.
 */
export function downsample<T extends { time: number }>(points: T[], maxPoints: number): T[] {
  if (maxPoints < 2) throw new RangeError('downsample keeps at least 2 points');
  if (points.length <= maxPoints) return [...points];
  const inner = points.slice(1, -1);
  const buckets = maxPoints - 2;
  const out: T[] = [points[0] as T];
  for (let b = 0; b < buckets; b++) {
    const from = Math.floor((b * inner.length) / buckets);
    const to = Math.floor(((b + 1) * inner.length) / buckets);
    out.push(averageBucket(inner.slice(from, to)));
  }
  out.push(points.at(-1) as T);
  return out;
}
