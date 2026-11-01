import { describe, expect, it, vi } from 'vitest';
import { lazyScope } from '../../../src/unifi/write-tools/index.js';
import { emptyScope } from '../../helpers/sdk.js';

describe('lazyScope', () => {
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
});
