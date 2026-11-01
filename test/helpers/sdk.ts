// Helpers for driving tools through the MCP SDK, the path production uses:
// the SDK parses the raw zod shape (src/mcp/server.ts registerTool) before a
// handler sees anything. Shared by every file that pins a confirm-level tool.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { expect, type Mock } from 'vitest';
import { createServer } from '../../src/mcp/server.js';
import type { ProtectedScope } from '../../src/unifi/guard.js';

/** An MCP client connected in memory to a server holding `tools`. */
export async function connect(tools: Parameters<typeof createServer>[0]): Promise<Client> {
  const server = createServer(tools);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 't', version: '0' });
  await Promise.all([client.connect(ct), server.connect(st)]);
  return client;
}

/** Everything a confirm-level tool must refuse to treat as a confirmation. */
export const LOOSE_CONFIRMS: unknown[] = ['true', 1, 'yes', {}, [true], false, null, 'false', 0];

/** Each loose confirm either errors at the SDK or returns the preview; none reaches `spy`. */
export async function expectRejectsLooseConfirm(
  client: Client,
  name: string,
  args: Record<string, unknown>,
  spy: Mock,
): Promise<void> {
  for (const confirm of LOOSE_CONFIRMS) {
    const r = await client.callTool({ name, arguments: { ...args, confirm } });
    const text = JSON.stringify(r.content);
    const refused = r.isError === true || text.includes('confirm: true');
    expect(refused, `${name} confirm=${JSON.stringify(confirm)}: ${text}`).toBe(true);
    expect(spy, `${name} ran on confirm=${JSON.stringify(confirm)}`).not.toHaveBeenCalled();
  }
}

/** A scope that protects nothing (not even a gateway); fresh sets each call. */
export function emptyScope(): ProtectedScope {
  return {
    networkIds: new Set(),
    subnets: [],
    gatewayDeviceIds: new Set(),
    uplinkDeviceIds: new Set(),
    devices: new Map(),
    networkNames: new Map(),
  };
}
