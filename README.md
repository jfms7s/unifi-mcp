# unifi-mcp

An MCP server for a UniFi network. It lets an LLM client diagnose the network (devices, clients, WAN, VPN, events), read metrics and traffic reports, summarise threats, audit the security posture, and make guarded changes to clients, devices, networks, WiFi, hotspot vouchers and the zone-based firewall (policies, zones, ACL rules, DNS policies, traffic matching lists and an IP blocklist).

**Important:** the write tools change the live network. A bad network or WiFi change can cut clients off, and a restart can take the gateway down. Changes that could lock unifi-mcp itself out are previewed first and only run with `confirm=true` (see [Protected networks](#protected-networks)). Give the server a key from a **dedicated local admin** (see [Create the API key](#create-the-api-key)), and set `UNIFI_MCP_READ_ONLY=true` if you only want to look.

## Tools

The guard column says what a change needs before it runs:

- **none**: runs straight away (reads, and changes that cannot lock anything out).
- **confirm if protected**: previews unless `confirm=true` when the target is on, or feeds, a protected network or is the gateway, or when a firewall policy, zone, ACL rule or blocked address can reach a protected network.
- **always confirm**: always previews first; runs only with `confirm=true`.

`site` is optional on every tool; with one site the tool uses it.

| Tool | Guard | What it does |
|---|---|---|
| `unifi_overview` | read | The "is anything wrong?" entry point: console, health per subsystem, devices and clients, recent HIGH events. |
| `unifi_list_devices` | read | Devices with state, firmware, uptime, CPU and memory, and a summary: uplink (parent and port, `WAN` for the gateway, the last one for an offline device), ports up and PoE in use, and AP radios with channel and clients. |
| `unifi_get_device` | read | One device in detail. |
| `unifi_list_clients` | read | Clients, newest activity first; filter by network, offline, blocked. |
| `unifi_get_client` | read | One client in detail. |
| `unifi_wan_status` | read | WAN state, ISP, latency and drops. |
| `unifi_vpn_status` | read | VPN servers and site-to-site tunnels. |
| `unifi_events` | read | The event log, newest first, paged to a ceiling that is reported when hit. |
| `unifi_threat_summary` | read | SECURITY log entries grouped and checked against port forwards; firewall blocks are grouped by rule and LAN address, inbound or outbound. |
| `unifi_posture_audit` | read | Security posture findings, HIGH first; rules that could not run are listed under `skipped`, findings accepted with `UNIFI_MCP_ACCEPTED_FINDINGS` under `accepted`. |
| `unifi_list_firewall` | read | Zones, zone policies, ACL rules, DNS policies and traffic matching lists as one-line rules; a rule repeated across zone pairs is one row. A collection that cannot be read is named under `unavailable`; without the zones, policy sides read `zone <id prefix>`. |
| `unifi_list_port_forwards` | read | Port forwards, enabled state and exposure. |
| `unifi_list_wifi` | read | WiFi networks with security, network and guest flags. |
| `unifi_list_networks` | read | Networks with VLAN, subnet, DHCP and isolation. |
| `unifi_audit_log` | read | Who changed what and when; filter by `actor`. |
| `unifi_traffic_report` | read | Traffic and client counts over time for the site, an AP, a client or the gateway. `device` must be an AP (scope `ap`) or a gateway (scope `gateway`); `client` is only for scope `client`. |
| `unifi_top_apps` | read | Top applications and categories by traffic. |
| `unifi_isp_metrics` | read | ISP latency, loss and uptime from Site Manager (needs `UNIFI_SITE_MANAGER_API_KEY`). |
| `unifi_list_hosts` | read | Consoles on the Site Manager account (needs `UNIFI_SITE_MANAGER_API_KEY`). |
| `unifi_block_client` | confirm if protected | Block a client. |
| `unifi_unblock_client` | none | Unblock a client. |
| `unifi_reconnect_client` | confirm if protected | Disconnect a client so it reconnects. |
| `unifi_authorize_guest` | confirm if protected | Authorize a guest client. |
| `unifi_unauthorize_guest` | confirm if protected | Revoke a guest's authorization. |
| `unifi_restart_device` | confirm if protected | Restart a device; the gateway and anything carrying a protected network need `confirm=true`. |
| `unifi_power_cycle_port` | confirm if protected | Power-cycle PoE on a switch port. |
| `unifi_locate_device` | none | Turn a device's locate LED on or off. |
| `unifi_adopt_device` | none | Adopt a device waiting for adoption. |
| `unifi_unadopt_device` | always confirm | Remove a device (an online one is factory-reset). |
| `unifi_create_network` | none | Create a network. |
| `unifi_update_network` | always confirm | Change a network; the preview shows before and after. |
| `unifi_delete_network` | always confirm | Delete a network. |
| `unifi_create_wifi` | none | Create a WiFi broadcast. |
| `unifi_update_wifi` | always confirm | Change a WiFi broadcast; a passphrase change is never shown back. |
| `unifi_set_wifi_enabled` | always confirm | Turn a WiFi broadcast on or off. |
| `unifi_delete_wifi` | always confirm | Delete a WiFi broadcast. |
| `unifi_create_vouchers` | none | Generate hotspot vouchers. |
| `unifi_delete_voucher` | none | Delete one voucher. |
| `unifi_delete_vouchers` | always confirm | Delete every voucher a filter matches. |
| `unifi_create_firewall_policy` | confirm if protected | Create a zone policy; zones by name. |
| `unifi_update_firewall_policy` | always confirm | Change a user-defined zone policy; the preview shows before and after. |
| `unifi_set_firewall_policy_enabled` | confirm if protected | Turn a user-defined zone policy on or off. |
| `unifi_delete_firewall_policy` | always confirm | Delete a user-defined zone policy. |
| `unifi_reorder_firewall_policies` | always confirm | Set the order of a zone pair's user-defined policies. |
| `unifi_create_firewall_zone` | confirm if protected | Create a custom zone, for example to give IoT a zone of its own. |
| `unifi_update_firewall_zone` | always confirm | Rename a custom zone or set its networks. |
| `unifi_delete_firewall_zone` | always confirm | Delete a custom zone. |
| `unifi_create_acl_rule` | confirm if protected | Create a switch ACL rule. |
| `unifi_update_acl_rule` | always confirm | Change a user-defined ACL rule. |
| `unifi_delete_acl_rule` | always confirm | Delete a user-defined ACL rule. |
| `unifi_create_dns_policy` | confirm if it names the console | Create a local DNS record or forward domain. When `UNIFI_URL` is a hostname, a record for it, or a forward of it or a parent domain, needs `confirm=true` (case and a trailing dot don't matter). |
| `unifi_update_dns_policy` | always confirm | Change a DNS policy. |
| `unifi_delete_dns_policy` | always confirm | Delete a DNS policy. |
| `unifi_create_traffic_list` | none | Create a traffic matching list (IPv4, IPv6 or ports). |
| `unifi_update_traffic_list` | always confirm | Rename a traffic matching list or replace its items; the preview names the policies that use it. |
| `unifi_delete_traffic_list` | always confirm | Delete a traffic matching list. |
| `unifi_block_ip` | confirm if protected | Block an IPv4 address or CIDR both ways through the `unifi-mcp blocklist`; the first call creates the list and its two policies and needs `confirm=true` once. A range wider than /16 (prefix shorter than 16) needs `confirm=true` too. |
| `unifi_unblock_ip` | confirm if protected | Take an address off the blocklist; removing the last one deletes the blocklist and needs `confirm=true`, as does a range wider than /16. |

With a Site Manager key there are 58 tools (56 without). In read-only mode only the 19 read tools (17 without the key) are registered.

The zone policy and zone tools and the blocklist need Zone-Based Firewall (UniFi UI, Settings → Policy Engine); while it is off they say so and change nothing, and `unifi_list_firewall` shows the old-style rules instead. System-defined policies and zones are UniFi's and are refused, as are the IPS auto-blocks, which the console lists without an id.

If the console's official client list doesn't answer, the client tools (`unifi_list_clients`, `unifi_get_client`, the client scope of `unifi_traffic_report` and `unifi_top_apps`) fall back to the legacy client records and say so in a `note`, and `unifi_overview` counts the connected clients from the legacy station list (`clientsNote`). Block, unblock and reconnect still work; guest authorize and unauthorize refuse until the official list answers. If only the WAN list fails, `unifi_posture_audit` still runs its zone rules, shows WANs by id and says so in a `note`.

## Protected networks

`UNIFI_MCP_PROTECTED_NETWORKS` (default value `pi-cluster`; for example `servers,management` to set your own) names the networks unifi-mcp must not cut itself, or what runs on them, off from. A comma-separated list of names or ids; names ignore case. The guard works out the clients on those networks, the subnets, the devices and ports that carry them (including through daisy-chained switches and APs) and the gateway. A change that touches any of them previews first and runs only with `confirm=true`. A client or device the guard cannot place leans to confirm.

The names are looked up when the first change runs and again every five minutes, so a newly adopted device or a changed subnet is picked up without a restart. An unknown name is an error that lists the networks that exist, so a typo never leaves a network unprotected. An empty value is a startup error too; to protect only the gateway, say so with `none`. The protected list is logged at startup, as a warning when it is `none`. **Renaming a protected network makes the guard refuse changes until `UNIFI_MCP_PROTECTED_NETWORKS` is updated to the new name** (or use the network's id).

On a console with more than one site, every change names its site (`site`), and the guard works out the protected scope of that site: the names are looked up among that site's networks, and each site's scope is cached on its own. A site that has none of the protected networks protects only its gateway. A name that is on no site of the console is the unknown-name error above.

The machine running unifi-mcp is protected only if it sits on a protected network. A stdio run on a desktop on another network can block or disconnect that desktop without a confirm. Run read-only there, or add the desktop's network to `UNIFI_MCP_PROTECTED_NETWORKS`.

A firewall policy's side that is a zone alone reaches every network in that zone. The default Internal zone holds every LAN, pi-cluster included, so a policy touching the Internal zone is confirm-level unless its filters provably exclude pi-cluster: a NETWORK filter naming only other networks, or IPv4 addresses, ranges or subnets (directly or through an IPv4 traffic matching list) outside pi-cluster's subnet. Addresses that overlap a protected subnet are confirm-level in any zone. Anything the guard cannot place leans to confirm: an unknown zone, list or network id, an IPv6 address, an opposite match, or a MAC, port or other filter, which counts as the whole zone.

Write tools act only on an exact client or device: an id, MAC, IP or full name. A partial name comes back as candidates to ask again with, and nothing changes.

## Accepted posture findings

Some exposure is intended: a port forward you run on purpose, an SSID kept on WPA2 for old devices. `UNIFI_MCP_ACCEPTED_FINDINGS` lists those findings so `unifi_posture_audit` stops raising them on every run:

```
UNIFI_MCP_ACCEPTED_FINDINGS=port-forward-open:PLEX,port-forward-open:reverse,wifi-weak:TP-Link_D3C0,policy-any-any:Allow Internal to IoT
```

Each entry is `rule:object`, comma-separated: the rule name a finding carries and its `object`, exactly as the audit prints it (case counts, no prefixes; the object is everything after the first colon, so it may hold a colon but not a comma). An accepted finding is not dropped: it moves to `accepted` with its severity and leaves `counts`. One entry accepts every finding of that rule on that object, so `wifi-weak:<ssid>` also covers a later guest-isolation finding on the same SSID.

An entry that matches no finding (the forward was removed or renamed) is listed under `staleAccepted`, so the list can't rot unseen. An entry whose rule was skipped this run (zone rules while Zone-Based Firewall is off) is not stale. An unknown rule name or an entry without an object is a startup error; the accepted list is logged at startup.

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `UNIFI_URL` | yes | Console URL, e.g. `https://192.168.1.1`. |
| `UNIFI_API_KEY` | yes | The console's API key (see below). |
| `UNIFI_TLS_FINGERPRINT` | yes, unless `UNIFI_TLS_INSECURE=true` | SHA-256 fingerprint of the console's certificate; the connection is pinned to it. |
| `UNIFI_TLS_INSECURE` | no | `true` turns certificate checks off. Local experiments only. |
| `UNIFI_SITE_MANAGER_API_KEY` | no | Site Manager (unifi.ui.com) key; adds `unifi_list_hosts` and `unifi_isp_metrics`. |
| `UNIFI_MCP_READ_ONLY` | no | `true` registers the read tools only. |
| `UNIFI_MCP_PROTECTED_NETWORKS` | no | Comma-separated network names or ids. The default value is `pi-cluster`; set your own, e.g. `servers,management`, or `none` to protect only the gateway. Empty is an error. |
| `UNIFI_MCP_ACCEPTED_FINDINGS` | no | Comma-separated `rule:object` posture findings accepted as intended; see [Accepted posture findings](#accepted-posture-findings). Unset or empty accepts none. |
| `UNIFI_MCP_TRANSPORT` | no | `stdio` (default), `http` or `both`. The image sets `http`. |
| `UNIFI_MCP_PORT` | no | HTTP port, default `3000`. |
| `UNIFI_MCP_TOKEN` | for `http`/`both` | Bearer token MCP clients must send. |

The HTTP transport serves MCP at `/mcp` (bearer auth) and an unauthenticated `/healthz` for probes. Requests to the console time out after 15 seconds.

### Get the fingerprint

```bash
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

Pass the value after `sha256 Fingerprint=` as `UNIFI_TLS_FINGERPRINT`. UniFi OS regenerates its certificate on some upgrades; unifi-mcp then reports "console certificate changed: expected …, got …" and you update the fingerprint.

### Create the API key

Create a dedicated **local** admin named `unifi-mcp` with the **full** administrator role (the Network API keys inherit their user's rights), sign in as it once, and create the key there. The menu depends on your Network version: **Settings → Control Plane → Integrations**, or **Settings → Integrations**. A dedicated admin means the audit log can tell unifi-mcp's changes from yours: `unifi_audit_log` takes `actor: 'unifi-mcp'`.

## Run

```bash
docker run --rm -p 3000:3000 \
  -e UNIFI_URL=https://192.168.1.1 \
  -e UNIFI_API_KEY=your-api-key \
  -e UNIFI_TLS_FINGERPRINT=AA:BB:...:FF \
  -e UNIFI_MCP_TOKEN=a-long-random-secret \
  ghcr.io/jfms7s/unifi-mcp:v0.3.0
```

Pin a `vX.Y.Z` tag, not `latest`, so an upgrade is a decision you make.

Claude Code (`~/.claude.json`, `mcpServers`), over HTTP:

```json
"unifi": {
  "type": "http",
  "url": "https://unifi-mcp.example.com/mcp",
  "headers": { "Authorization": "Bearer a-long-random-secret" }
}
```

### From source

```bash
git clone https://github.com/jfms7s/unifi-mcp.git
cd unifi-mcp
npm ci
npm run build
```

Then point Claude Code at the build, over stdio:

```json
"unifi": {
  "type": "stdio",
  "command": "node",
  "args": ["/path/to/unifi-mcp/dist/index.js"],
  "env": {
    "UNIFI_URL": "https://192.168.1.1",
    "UNIFI_API_KEY": "your-api-key",
    "UNIFI_TLS_FINGERPRINT": "AA:BB:...:FF",
    "UNIFI_MCP_READ_ONLY": "true"
  }
}
```

## Development

```bash
npm ci
npm run typecheck
npm run lint
npm run format:check   # npm run format to fix
npm test              # npm run test:coverage for an lcov report
npm run build
```

Tests mock all HTTP with msw; no console is needed. `npm run smoke` calls every read tool once against a live console (set the variables above first) and prints each tool's name, OK or ERR and the size of its output, never the output. It is never run in CI.
