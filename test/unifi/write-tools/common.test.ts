import { afterEach, describe, expect, it, vi } from 'vitest';
import { lazyScope } from '../../../src/unifi/write-tools/index.js';
import type { Site } from '../../../src/unifi/sites.js';
import { emptyScope } from '../../helpers/sdk.js';

const A: Site = { id: 'site-a', ref: 'default', name: 'Default' };
const B: Site = { id: 'site-b', ref: 'branch', name: 'Branch' };

describe('lazyScope', () => {
  afterEach(() => vi.useRealTimers());

  it('loads on first use, then serves the same scope', async () => {
    const load = vi.fn(async () => emptyScope());
    const scope = lazyScope(load);
    expect(load).not.toHaveBeenCalled();
    const [a, b] = await Promise.all([scope(A), scope(A)]);
    expect(await scope(A)).toBe(a);
    expect(b).toBe(a);
    expect(load).toHaveBeenCalledOnce();
  });

  it('keeps one scope per site, each loaded for its own site', async () => {
    const scopes = new Map([
      [A.id, emptyScope()],
      [B.id, emptyScope()],
    ]);
    const load = vi.fn(async (site: Site) => scopes.get(site.id)!);
    const scope = lazyScope(load);
    expect(await scope(A)).toBe(scopes.get(A.id));
    expect(await scope(B)).toBe(scopes.get(B.id));
    expect(await scope(A)).toBe(scopes.get(A.id));
    expect(await scope(B)).toBe(scopes.get(B.id));
    expect(load.mock.calls.map(([site]) => site.id)).toEqual([A.id, B.id]);
  });

  it('a failed load on one site leaves the other site cached', async () => {
    const good = emptyScope();
    const load = vi
      .fn<(site: Site) => Promise<ReturnType<typeof emptyScope>>>()
      .mockResolvedValueOnce(good)
      .mockRejectedValueOnce(new Error('branch unreachable'))
      .mockResolvedValueOnce(emptyScope());
    const scope = lazyScope(load);
    expect(await scope(A)).toBe(good);
    await expect(scope(B)).rejects.toThrow('branch unreachable');
    expect(await scope(A)).toBe(good);
    await expect(scope(B)).resolves.toBeDefined();
    expect(load.mock.calls.map(([site]) => site.id)).toEqual([A.id, B.id, B.id]);
  });

  it('does not keep a failed load: the next change tries again', async () => {
    const load = vi
      .fn<(site: Site) => Promise<ReturnType<typeof emptyScope>>>()
      .mockRejectedValueOnce(new Error('Protected network "k3s" is not on this console'))
      .mockResolvedValueOnce(emptyScope());
    const scope = lazyScope(load);
    await expect(scope(A)).rejects.toThrow('k3s');
    await expect(scope(A)).resolves.toBeDefined();
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('reloads after the TTL, so a later adoption or subnet change is seen', async () => {
    vi.useFakeTimers();
    const first = emptyScope();
    const second = emptyScope();
    const load = vi
      .fn<(site: Site) => Promise<ReturnType<typeof emptyScope>>>()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);
    const scope = lazyScope(load);
    expect(await scope(A)).toBe(first);
    vi.advanceTimersByTime(4 * 60_000);
    expect(await scope(A)).toBe(first);
    expect(load).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(61_000);
    expect(await scope(A)).toBe(second);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('does not cache a failed reload after the TTL', async () => {
    vi.useFakeTimers();
    const first = emptyScope();
    const third = emptyScope();
    const load = vi
      .fn<(site: Site) => Promise<ReturnType<typeof emptyScope>>>()
      .mockResolvedValueOnce(first)
      .mockRejectedValueOnce(new Error('console unreachable'))
      .mockResolvedValueOnce(third);
    const scope = lazyScope(load);
    await scope(A);
    vi.advanceTimersByTime(5 * 60_000 + 1);
    await expect(scope(A)).rejects.toThrow('unreachable');
    expect(await scope(A)).toBe(third);
  });
});
