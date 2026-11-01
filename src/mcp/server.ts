import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describeError } from '../http/errors.js';
import type { ToolDefinition } from './types.js';

// Read at runtime rather than imported: package.json sits outside rootDir
// ("src"), so a JSON import would nest the build output under dist/src. The
// relative path resolves from both src/mcp (tests) and dist/mcp (the image).
const { version } = createRequire(import.meta.url)('../../package.json') as { version: string };

export function toolResult(value: unknown): { content: Array<{ type: 'text'; text: string }> } {
  const text = value === undefined ? 'Success.' : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function createServer(tools: ToolDefinition[]): McpServer {
  const server = new McpServer({ name: 'unifi-mcp', version });

  for (const tool of tools) {
    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      async (args: Record<string, unknown>) => {
        try {
          return toolResult(await tool.handler(args));
        } catch (error) {
          return {
            content: [{ type: 'text' as const, text: describeError(error) }],
            isError: true,
          };
        }
      },
    );
  }

  return server;
}
