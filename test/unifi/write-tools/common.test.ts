import { afterEach, describe, expect, it, vi } from 'vitest';
import { lazyScope } from '../../../src/unifi/write-tools/index.js';
import { emptyScope } from '../../helpers/sdk.js';

describe('lazyScope', () => {
  afterEach(() => vi.useRealTimers());

  it('loads on first use, then serves the same scope', async () => {
    const load = vi.fn(async () => emptyScope());
    const scope = lazyScope(load);
    expect(load).not.toHaveBeenCalled();
    const [a, b] = await Promise.all([scope(), scope()]);
    expect(await scope()).toBe(a);
    expect(b).toBe(a);
    expect(load).toHaveBeenCalledOnce();
  });

  it('does not keep a failed load: the next change tries again', async () => {
    const load = vi
      .fn<() => Promise<ReturnType<typeof emptyScope>>>()
      .mockRejectedValueOnce(new Error('Protected network "k3s" is not on this console'))
      .mockResolvedValueOnce(emptyScope());
    const scope = lazyScope(load);
    await expect(scope()).rejects.toThrow('k3s');
    await expect(scope()).resolves.toBeDefined();
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('reloads after the TTL, so a later adoption or subnet change is seen', async () => {
    vi.useFakeTimers();
    const first = emptyScope();
    const second = emptyScope();
    const load = vi
      .fn<() => Promise<ReturnType<typeof emptyScope>>>()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);
    const scope = lazyScope(load);
    expect(await scope()).toBe(first);
    vi.advanceTimersByTime(4 * 60_000);
    expect(await scope()).toBe(first);
    expect(load).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(61_000);
    expect(await scope()).toBe(second);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('does not cache a failed reload after the TTL', async () => {
    vi.useFakeTimers();
    const first = emptyScope();
    const third = emptyScope();
    const load = vi
      .fn<() => Promise<ReturnType<typeof emptyScope>>>()
      .mockResolvedValueOnce(first)
      .mockRejectedValueOnce(new Error('console unreachable'))
      .mockResolvedValueOnce(third);
    const scope = lazyScope(load);
    await scope();
    vi.advanceTimersByTime(5 * 60_000 + 1);
    await expect(scope()).rejects.toThrow('unreachable');
    expect(await scope()).toBe(third);
  });
});
