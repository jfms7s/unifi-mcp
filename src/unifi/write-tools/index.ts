import type { ToolDefinition } from '../../mcp/types.js';
import { createClientWriteTools } from './clients.js';
import { createDeviceWriteTools } from './devices.js';
import { createNetworkWriteTools } from './networks.js';
import { createVoucherWriteTools } from './vouchers.js';
import { createWifiWriteTools } from './wifi.js';
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
  'unifi_create_network',
  'unifi_update_network',
  'unifi_delete_network',
  'unifi_create_wifi',
  'unifi_update_wifi',
  'unifi_set_wifi_enabled',
  'unifi_delete_wifi',
  'unifi_create_vouchers',
  'unifi_delete_voucher',
  'unifi_delete_vouchers',
] as const;

/** The change tools. Every change runs through guard.ts; Task 14 wires them in, unless read-only. */
export function createWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [
    ...createClientWriteTools(deps),
    ...createDeviceWriteTools(deps),
    ...createNetworkWriteTools(deps),
    ...createWifiWriteTools(deps),
    ...createVoucherWriteTools(deps),
  ];
}
