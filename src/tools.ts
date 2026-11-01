import type { UnifiMcpConfig } from './config.js';
import type { ToolDefinition } from './mcp/types.js';

export function buildTools(config: UnifiMcpConfig): ToolDefinition[] {
  void config; // tools arrive in later tasks
  return [];
}
