import express from 'express';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { bearerAuth } from './auth.js';

export async function startStdio(server: McpServer): Promise<void> {
  await server.connect(new StdioServerTransport());
}

export interface HttpHandle {
  port: number;
  close(): Promise<void>;
}

export async function startHttp(
  createMcpServer: () => McpServer,
  options: { port: number; token: string },
): Promise<HttpHandle> {
  const app = express();

  // Deliberately before bearerAuth and deliberately contentless: a Kubernetes
  // probe cannot present a token, and /mcp answers an unauthenticated request
  // with 401, which a probe reads as a failing container. Reaching here proves
  // the event loop is still serving -- it says nothing about UniFi, and
  // must never report on it, since that would take the pod down for an outage
  // outside it.
  app.get('/healthz', (_request, response) => {
    response.type('text/plain').send('ok');
  });

  app.all('/mcp', bearerAuth(options.token), express.json(), (request, response) => {
    void (async () => {
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      response.on('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(request, response, request.body);
    })().catch(() => {
      if (!response.headersSent) response.status(500).json({ error: 'internal error' });
    });
  });

  const listener = app.listen(options.port);
  await new Promise<void>((resolve, reject) => {
    listener.once('listening', resolve);
    listener.once('error', reject);
  });

  const addr = listener.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : options.port;

  return {
    port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        listener.close((error) => (error ? reject(error) : resolve()));
        // close() alone stops new connections but waits for keep-alive ones to
        // go idle on their own, which a polling MCP client may never do.
        listener.closeIdleConnections();
      }),
  };
}
