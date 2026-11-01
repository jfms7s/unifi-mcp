// The change guard through the path production uses: the MCP SDK parses the raw
// zod shape (src/mcp/server.ts registerTool), not a direct handler call. Pins
// that an SDK or zod upgrade can't start coercing `confirm` or forwarding
// unknown keys, either of which would let a guarded change run unconfirmed.
// Every confirm-level tool gets its own describe block here.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it, vi, type Mock } from 'vitest';
import { z } from 'zod';
import { createServer } from '../../src/mcp/server.js';
import { defineTool } from '../../src/mcp/types.js';
import { guarded, type ProtectedScope } from '../../src/unifi/guard.js';
import { confirmInput } from '../../src/unifi/inputs.js';

async function connect(tools: Parameters<typeof createServer>[0]) {
  const server = createServer(tools);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 't', version: '0' });
  await Promise.all([client.connect(ct), server.connect(st)]);
  return client;
}

/** Everything a confirm-level tool must refuse to treat as a confirmation. */
export const LOOSE_CONFIRMS: unknown[] = ['true', 1, 'yes', {}, [true], false, null, 'false', 0];

/** Each loose confirm either errors at the SDK or returns the preview; none reaches `run`. */
export async function expectRejectsLooseConfirm(
  client: Client,
  name: string,
  args: Record<string, unknown>,
  spy: Mock,
) {
  for (const confirm of LOOSE_CONFIRMS) {
    const r = await client.callTool({ name, arguments: { ...args, confirm } });
    const text = JSON.stringify(r.content);
    const refused = r.isError === true || text.includes('confirm: true');
    expect(refused, `${name} confirm=${JSON.stringify(confirm)}: ${text}`).toBe(true);
    expect(spy, `${name} ran on confirm=${JSON.stringify(confirm)}`).not.toHaveBeenCalled();
  }
}

const emptyScope: ProtectedScope = {
  networkIds: new Set(),
  subnets: [],
  gatewayDeviceIds: new Set(),
  uplinkDeviceIds: new Set(),
  devices: new Map(),
  networkNames: new Map(),
};

function stubTool() {
  const run = vi.fn(async () => ({ done: true }));
  const preview = vi.fn(async () => ({ would: 'do it' }));
  const seen: Array<Record<string, unknown>> = [];
  const tool = defineTool({
    name: 'unifi_stub',
    description: 'stub confirm-level tool',
    inputSchema: { target: z.string(), confirm: confirmInput },
    annotations: { readOnlyHint: false },
    handler: async (args) => {
      seen.push(args);
      return guarded({ level: 'confirm', confirm: args.confirm, preview, run }, emptyScope, []);
    },
  });
  return { tool, run, preview, seen };
}

describe('guard through the MCP SDK: stub confirm-level tool', () => {
  it('refuses every loose confirm and never runs', async () => {
    const { tool, run } = stubTool();
    const client = await connect([tool]);
    await expectRejectsLooseConfirm(client, 'unifi_stub', { target: 'x' }, run);
  });

  it('string, number, object and array confirms are schema errors', async () => {
    const { tool, run, seen } = stubTool();
    const client = await connect([tool]);
    for (const confirm of ['true', 1, 'yes', {}, [true]]) {
      const r = await client.callTool({ name: 'unifi_stub', arguments: { target: 'x', confirm } });
      expect(r.isError, JSON.stringify(confirm)).toBe(true);
    }
    expect(run).not.toHaveBeenCalled();
    expect(seen).toEqual([]);
  });

  it('confirm: false is a schema error too (z.literal(true) refuses it)', async () => {
    const { tool, run } = stubTool();
    const client = await connect([tool]);
    const r = await client.callTool({ name: 'unifi_stub', arguments: { target: 'x', confirm: false } });
    expect(r.isError).toBe(true);
    expect(run).not.toHaveBeenCalled();
  });

  it('an absent confirm returns the preview, not an error', async () => {
    const { tool, run, preview } = stubTool();
    const client = await connect([tool]);
    const r = await client.callTool({ name: 'unifi_stub', arguments: { target: 'x' } });
    expect(r.isError).toBeFalsy();
    expect(JSON.stringify(r.content)).toContain('confirm: true');
    expect(preview).toHaveBeenCalledOnce();
    expect(run).not.toHaveBeenCalled();
  });

  it('unknown keys never reach the handler', async () => {
    const { tool, seen } = stubTool();
    const client = await connect([tool]);
    await client.callTool({
      name: 'unifi_stub',
      arguments: { target: 'x', force: true, yes: true, confirmed: true },
    });
    await client.callTool({
      name: 'unifi_stub',
      arguments: { target: 'x', confirm: true, force: true, yes: true },
    });
    expect(seen).toHaveLength(2);
    for (const args of seen) {
      expect(Object.keys(args).sort()).not.toContain('force');
      expect(args).not.toHaveProperty('yes');
      expect(args).not.toHaveProperty('confirmed');
    }
  });

  it('unknown keys are no substitute for confirm', async () => {
    const { tool, run } = stubTool();
    const client = await connect([tool]);
    for (const extra of [{ force: true }, { yes: true }, { confirmed: true }]) {
      await client.callTool({ name: 'unifi_stub', arguments: { target: 'x', ...extra } });
    }
    expect(run).not.toHaveBeenCalled();
  });

  it('confirm: true runs exactly once', async () => {
    const { tool, run, preview } = stubTool();
    const client = await connect([tool]);
    const r = await client.callTool({ name: 'unifi_stub', arguments: { target: 'x', confirm: true } });
    expect(r.isError).toBeFalsy();
    expect(run).toHaveBeenCalledOnce();
    expect(preview).not.toHaveBeenCalled();
  });
});
