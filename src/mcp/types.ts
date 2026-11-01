import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { z, ZodRawShape } from 'zod';

export interface ToolDefinition<Shape extends ZodRawShape = ZodRawShape> {
  name: string;
  description: string;
  inputSchema: Shape;
  /** Required so no tool ships without saying whether it reads or changes CI. */
  annotations: ToolAnnotations;
  handler: (args: z.infer<z.ZodObject<Shape>>) => Promise<unknown>;
}

export function defineTool<Shape extends ZodRawShape>(
  definition: ToolDefinition<Shape>,
): ToolDefinition {
  return definition as unknown as ToolDefinition;
}
