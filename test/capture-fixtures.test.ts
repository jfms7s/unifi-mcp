import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { writeFixtures } from '../scripts/capture-fixtures.js';

describe('writeFixtures', () => {
  let root: string;
  let outDir: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'unifi-fixtures-'));
    outDir = join(root, 'live');
    await mkdir(outDir);
    await writeFile(join(outDir, 'old.json'), '{"old":true}\n');
  });
  afterEach(() => rm(root, { recursive: true, force: true }));

  it('leaves the previous fixtures in place and fails when any endpoint failed', async () => {
    const captured = [{ name: 'legacy-stat-sta', data: { data: [] } }];
    await expect(writeFixtures(captured, ['rest/user: timed out'], outDir)).rejects.toThrow(
      /capture incomplete[\s\S]*rest\/user: timed out/,
    );
    expect(await readdir(outDir)).toEqual(['old.json']);
    expect(await readdir(root)).toEqual(['live']);
  });

  it('replaces the folder with scrubbed fixtures when everything was captured', async () => {
    const captured = [{ name: 'legacy-stat-sta', data: { data: [{ mac: 'a4:b1:c2:d3:e4:f5' }] } }];
    await writeFixtures(captured, [], outDir);
    expect(await readdir(outDir)).toEqual(['legacy-stat-sta.json']);
    expect(JSON.parse(await readFile(join(outDir, 'legacy-stat-sta.json'), 'utf8'))).toEqual({
      data: [{ mac: '02:00:00:00:00:01' }],
    });
    expect(await readdir(root)).toEqual(['live']);
  });
});
