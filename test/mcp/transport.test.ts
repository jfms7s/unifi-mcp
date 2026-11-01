import { afterEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';
import { createServer } from '../../src/mcp/server.js';
import { defineTool } from '../../src/mcp/types.js';
import { startHttp } from '../../src/mcp/transport.js';

const testTool = defineTool({
  name: 'test_echo',
  description: 'Echo input back',
  inputSchema: { text: z.string() },
  annotations: { readOnlyHint: true },
  handler: async ({ text }) => ({ text }),
});

const token = 'test-secret-token';

describe('startHttp', () => {
  let handle: Awaited<ReturnType<typeof startHttp>> | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = null;
    }
  });

  it('serves several MCP requests with a valid token', async () => {
    handle = await startHttp(() => createServer([testTool]), { port: 0, token });
    const transport = new StreamableHTTPClientTransport(new URL(`http://localhost:${handle.port}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: 'test', version: '0.0.0' });
    await client.connect(transport);

    expect((await client.listTools()).tools.map((t) => t.name)).toEqual(['test_echo']);
    expect((await client.callTool({ name: 'test_echo', arguments: { text: 'a' } })).isError).toBeFalsy();
    expect((await client.callTool({ name: 'test_echo', arguments: { text: 'b' } })).isError).toBeFalsy();
    await client.close();
  });

  it.each([undefined, 'Bearer wrong-token'])('answers 401 to authorization %s without leaking the token', async (header) => {
    handle = await startHttp(() => createServer([testTool]), { port: 0, token });
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (header) headers.Authorization = header;
    const response = await fetch(`http://localhost:${handle.port}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {}, id: 1 }),
    });
    expect(response.status).toBe(401);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: 'unauthorized' });
    expect(body).not.toContain(token);
  });

  it('serves /healthz without a token', async () => {
    handle = await startHttp(() => createServer([testTool]), { port: 0, token });
    const response = await fetch(`http://localhost:${handle.port}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('ok');
  });
});
