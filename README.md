# unifi-mcp

An MCP server for a UniFi network. It lets an LLM client diagnose the network (devices, clients, WAN, VPN, events), read metrics and traffic reports, summarise threats, audit the security posture, and make guarded changes to clients, devices, networks, WiFi and hotspot vouchers.

**Important:** the write tools change the live network. A bad network or WiFi change can cut clients off, and a restart can take the gateway down. Changes that could lock unifi-mcp itself out are previewed first and only run with `confirm=true` (see [Protected networks](#protected-networks)). Give the server a key from a **dedicated local admin** (see [Create the API key](#create-the-api-key)), and set `UNIFI_MCP_READ_ONLY=true` if you only want to look.

## Tools

The guard column says what a change needs before it runs:

- **none**: runs straight away (reads, and changes that cannot lock anything out).
- **confirm if protected**: previews unless `confirm=true` when the target is on, or feeds, a protected network or is the gateway.
- **always confirm**: always previews first; runs only with `confirm=true`.

`site` is optional on every tool; with one site the tool uses it.

| Tool | Guard | What it does |
|---|---|---|
| `unifi_overview` | read | The "is anything wrong?" entry point: console, health per subsystem, devices and clients, recent HIGH events. |
| `unifi_list_devices` | read | Devices with state, firmware, uptime, CPU and memory. |
| `unifi_get_device` | read | One device in detail. |
| `unifi_list_clients` | read | Clients, newest activity first; filter by network, offline, blocked. |
| `unifi_get_client` | read | One client in detail. |
| `unifi_wan_status` | read | WAN state, ISP, latency and drops. |
| `unifi_vpn_status` | read | VPN servers and site-to-site tunnels. |
| `unifi_events` | read | The event log, newest first, paged to a ceiling that is reported when hit. |
| `unifi_threat_summary` | read | SECURITY log entries grouped and checked against port forwards. |
| `unifi_posture_audit` | read | Security posture findings, HIGH first. |
| `unifi_list_firewall` | read | Zones, zone policies, ACL rules and DNS policies as one-line rules. |
| `unifi_list_port_forwards` | read | Port forwards, enabled state and exposure. |
| `unifi_list_wifi` | read | WiFi networks with security, network and guest flags. |
| `unifi_list_networks` | read | Networks with VLAN, subnet, DHCP and isolation. |
| `unifi_audit_log` | read | Who changed what and when; filter by `actor`. |
| `unifi_traffic_report` | read | Traffic and client counts over time for the site, an AP, a client or the gateway. |
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

With a Site Manager key there are 39 tools (37 without). In read-only mode only the 19 read tools (17 without the key) are registered.

Firewall changes need Zone-Based Firewall, which has to be switched on in the UniFi UI (Settings → Policy Engine). The firewall write tools will come in a later release; `unifi_list_firewall` works today.

## Protected networks

`UNIFI_MCP_PROTECTED_NETWORKS` (default value `pi-cluster`; for example `servers,management` to set your own) names the networks unifi-mcp must not cut itself, or what runs on them, off from. A comma-separated list of names or ids; names ignore case. The guard works out the clients on those networks, the subnets, the devices and ports that carry them (including through daisy-chained switches and APs) and the gateway. A change that touches any of them previews first and runs only with `confirm=true`. A client or device the guard cannot place leans to confirm.

The names are looked up when the first change runs and again every five minutes, so a newly adopted device or a changed subnet is picked up without a restart. An unknown name is an error that lists the networks that exist, so a typo never leaves a network unprotected. An empty value is a startup error too; to protect only the gateway, say so with `none`. The protected list is logged at startup, as a warning when it is `none`. **Renaming a protected network makes the guard refuse changes until `UNIFI_MCP_PROTECTED_NETWORKS` is updated to the new name** (or use the network's id).

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
  ghcr.io/jfms7s/unifi-mcp:v0.1.0
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
npm test
npm run build
```

Tests mock all HTTP with msw; no console is needed. `npm run smoke` calls every read tool once against a live console (set the variables above first) and prints each tool's name, OK or ERR and the size of its output, never the output. It is never run in CI.
