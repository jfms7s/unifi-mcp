import { readFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { UnifiApiError } from '../../src/http/errors.js';
import { createServer } from '../../src/mcp/server.js';
import { defineTool } from '../../src/mcp/types.js';

async function connect(tools: Parameters<typeof createServer>[0]) {
  const server = createServer(tools);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

const echoTool = defineTool({
  name: 'unifi_echo',
  description: 'Echo a number back',
  inputSchema: { number: z.number().int() },
  annotations: { readOnlyHint: true },
  handler: async ({ number }) => ({ number }),
});

describe('createServer', () => {
  it('reports the package.json version under the unifi-mcp name', async () => {
    const { version } = JSON.parse(
      readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
    ) as { version: string };
    const client = await connect([echoTool]);
    expect(client.getServerVersion()).toEqual({ name: 'unifi-mcp', version });
  });

  it('lists tools with their descriptions and annotations', async () => {
    const client = await connect([echoTool]);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['unifi_echo']);
    expect(tools[0]?.annotations).toEqual({ readOnlyHint: true });
  });

  it('returns the handler result as pretty-printed JSON text', async () => {
    const client = await connect([echoTool]);
    const result = await client.callTool({ name: 'unifi_echo', arguments: { number: 3 } });
    expect(result.content).toEqual([{ type: 'text', text: JSON.stringify({ number: 3 }, null, 2) }]);
    expect(result.isError).toBeFalsy();
  });

  it('turns a thrown error into a tool error result', async () => {
    const client = await connect([
      defineTool({
        name: 'unifi_boom',
        description: 'Always fails',
        inputSchema: {},
        annotations: { readOnlyHint: true },
        handler: async () => {
          throw new UnifiApiError({ kind: 'status', method: 'GET', path: '/api/x', status: 404, detail: 'not found' });
        },
      }),
    ]);
    const result = await client.callTool({ name: 'unifi_boom', arguments: {} });
    expect(result.isError).toBe(true);
    expect(result.content).toEqual([
      { type: 'text', text: 'UniFi returned 404 for GET /api/x: not found' },
    ]);
  });
});
