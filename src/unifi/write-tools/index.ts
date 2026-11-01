import type { ToolDefinition } from '../../mcp/types.js';
import { createAclWriteTools } from './acl.js';
import { createBlocklistWriteTools } from './blocklist.js';
import { createClientWriteTools } from './clients.js';
import { createDeviceWriteTools } from './devices.js';
import { createDnsWriteTools } from './dns.js';
import { createFirewallWriteTools } from './firewall.js';
import { createNetworkWriteTools } from './networks.js';
import { createTrafficListWriteTools } from './traffic-lists.js';
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
  'unifi_create_firewall_policy',
  'unifi_update_firewall_policy',
  'unifi_set_firewall_policy_enabled',
  'unifi_delete_firewall_policy',
  'unifi_reorder_firewall_policies',
  'unifi_create_firewall_zone',
  'unifi_update_firewall_zone',
  'unifi_delete_firewall_zone',
  'unifi_create_acl_rule',
  'unifi_update_acl_rule',
  'unifi_delete_acl_rule',
  'unifi_create_dns_policy',
  'unifi_update_dns_policy',
  'unifi_delete_dns_policy',
  'unifi_create_traffic_list',
  'unifi_update_traffic_list',
  'unifi_delete_traffic_list',
  'unifi_block_ip',
  'unifi_unblock_ip',
] as const;

/** The change tools. Every change runs through guard.ts; Task 14 wires them in, unless read-only. */
export function createWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [
    ...createClientWriteTools(deps),
    ...createDeviceWriteTools(deps),
    ...createNetworkWriteTools(deps),
    ...createWifiWriteTools(deps),
    ...createVoucherWriteTools(deps),
    ...createFirewallWriteTools(deps),
    ...createAclWriteTools(deps),
    ...createDnsWriteTools(deps),
    ...createTrafficListWriteTools(deps),
    ...createBlocklistWriteTools(deps),
  ];
}
