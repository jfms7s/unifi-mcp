import { describe, expect, it } from 'vitest';
import { buildTools } from '../src/tools.js';
import { WRITE_TOOL_NAMES } from '../src/unifi/write-tools/index.js';
import { testConfig } from './unifi/helpers.js';

const names = (tools: { name: string }[]) => tools.map((t) => t.name);

describe('buildTools', () => {
  it('read-only mode registers no tool that changes anything', () => {
    const tools = buildTools(testConfig({ readOnly: true, siteManagerApiKey: 'sm-key' }));
    expect(tools.length).toBeGreaterThan(0);
    expect(tools.filter((t) => t.annotations.readOnlyHint === false)).toEqual([]);
    for (const name of WRITE_TOOL_NAMES) expect(names(tools)).not.toContain(name);
  });

  it('registers every write tool when read-only is off', () => {
    const tools = names(buildTools(testConfig({ readOnly: false })));
    for (const name of WRITE_TOOL_NAMES) expect(tools).toContain(name);
  });

  it('leaves out the Site Manager tools without a key, and adds them with one', () => {
    const without = names(buildTools(testConfig({ siteManagerApiKey: undefined })));
    expect(without).not.toContain('unifi_list_hosts');
    expect(without).not.toContain('unifi_isp_metrics');
    const withKey = names(buildTools(testConfig({ siteManagerApiKey: 'sm-key' })));
    expect(withKey).toContain('unifi_list_hosts');
    expect(withKey).toContain('unifi_isp_metrics');
  });

  it('prefixes every name with unifi_ and keeps them unique', () => {
    const tools = names(buildTools(testConfig({ siteManagerApiKey: 'sm-key' })));
    expect(tools.every((n) => n.startsWith('unifi_'))).toBe(true);
    expect(new Set(tools).size).toBe(tools.length);
  });

  it('gives every tool all four annotations', () => {
    for (const tool of buildTools(testConfig({ siteManagerApiKey: 'sm-key' }))) {
      for (const hint of [
        'readOnlyHint',
        'destructiveHint',
        'idempotentHint',
        'openWorldHint',
      ] as const) {
        expect(typeof tool.annotations[hint], `${tool.name} ${hint}`).toBe('boolean');
      }
    }
  });
});
