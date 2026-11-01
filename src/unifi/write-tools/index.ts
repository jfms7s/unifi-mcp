import type { ToolDefinition } from '../../mcp/types.js';
import { createClientWriteTools } from './clients.js';
import { createDeviceWriteTools } from './devices.js';
import type { WriteDeps } from './common.js';

export { lazyScope, type WriteDeps } from './common.js';

/** Every write tool this module registers; tests pin the list. */
export const WRITE_TOOL_NAMES = [
  'unifi_block_client',
  'unifi_unblock_client',
  'unifi_reconnect_client',
  'unifi_authorize_guest',
  'unifi_unauthorize_guest',
  'unifi_restart_device',
  'unifi_power_cycle_port',
  'unifi_locate_device',
  'unifi_adopt_device',
  'unifi_unadopt_device',
] as const;

/** The change tools. Every change runs through guard.ts; Task 14 wires them in, unless read-only. */
export function createWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [...createClientWriteTools(deps), ...createDeviceWriteTools(deps)];
}
