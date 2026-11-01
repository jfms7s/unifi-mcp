// stat/device is not in the live capture (Task 3 recorded stat/device-basic,
// which carries no uplink). These bodies are hand-made in stat/device's shape
// (`uplink.uplink_mac` / `uplink.uplink_remote_port`, plus fields unifi-mcp
// ignores) for the four fixture devices: 1 udm, 2 usw, 1 uap.

export const GW_MAC = '02:00:00:00:00:01';
/** device-2, USW Ultra 60W: carries the k3s nodes. */
export const PI_SWITCH_MAC = '02:00:00:00:00:02';
/** device-3, U7 Lite. */
export const AP_MAC = '02:00:00:00:00:03';
/** device-4, USW Flex 2.5G 8 PoE: Default clients only. */
export const FLEX_MAC = '02:00:00:00:00:04';

export interface LinkSpec {
  mac: string;
  name: string;
  type: 'udm' | 'usw' | 'uap';
  uplinkMac?: string;
  uplinkPort?: number;
  /** An offline device only has `last_uplink`. */
  offline?: boolean;
}

/** As the console has it today: every device hangs off the gateway, except the AP, which the Flex powers. */
export const LIVE_LINKS: LinkSpec[] = [
  { mac: GW_MAC, name: 'Gateway CGU', type: 'udm' },
  { mac: PI_SWITCH_MAC, name: 'device-2', type: 'usw', uplinkMac: GW_MAC, uplinkPort: 3 },
  { mac: FLEX_MAC, name: 'device-4', type: 'usw', uplinkMac: GW_MAC, uplinkPort: 4 },
  { mac: AP_MAC, name: 'device-3', type: 'uap', uplinkMac: FLEX_MAC, uplinkPort: 8 },
];

/** The k3s switch daisy-chained behind the Flex's port 5, so nothing on the Flex itself is on pi-cluster. */
export const DAISY_CHAIN: LinkSpec[] = LIVE_LINKS.map((l) =>
  l.mac === PI_SWITCH_MAC ? { ...l, uplinkMac: FLEX_MAC, uplinkPort: 5 } : l,
);

export function statDevice(links: LinkSpec[]): unknown {
  return {
    meta: { rc: 'ok' },
    data: links.map((l) => {
      const uplink =
        l.uplinkMac === undefined
          ? { type: 'wire', name: 'eth4', up: true }
          : {
              type: 'wire',
              uplink_mac: l.uplinkMac,
              uplink_remote_port: l.uplinkPort,
              port_idx: 1,
              up: true,
            };
      return {
        _id: `legacy-${l.mac}`,
        mac: l.mac,
        name: l.name,
        type: l.type,
        model: 'X',
        state: l.offline ? 0 : 1,
        ...(l.offline ? { last_uplink: uplink } : { uplink }),
      };
    }),
  };
}
