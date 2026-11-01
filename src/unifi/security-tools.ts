import { z } from 'zod';
import { UnifiApiError } from '../http/errors.js';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { limitInput, parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import type { FirewallRule, NetworkConf, WlanConf } from './legacy.js';
import { sameText } from './lookup.js';
import type { FirewallPolicy, FirewallZone } from './official.js';
import { auditPosture, loadPostureInput, skippedRules } from './posture.js';
import { EVENT_CEILING, READ, coverageNote, type ReadDeps } from './read-common.js';
import { compact, cut, iso, renderMessage } from './shape.js';

export const LEGACY_RULES_LABEL = 'legacy rules (read-only until Zone-Based Firewall is on)';

const nonEmpty = (s: string | undefined) => (s ? s : undefined);

/** `WAN_IN #20000: DROP all 203.0.113.1 → 192.168.10.3 "name"`. */
function legacyRuleLine(r: FirewallRule, networkName: (id: string) => string | undefined): string {
  const side = (address?: string, networkId?: string, groups?: string[]) =>
    nonEmpty(address) ??
    (networkId ? (networkName(networkId) ?? `network ${networkId}`) : undefined) ??
    (groups?.length ? `group ${groups.join('+')}` : 'any');
  const src = side(r.src_address, r.src_networkconf_id, r.src_firewallgroup_ids);
  const dst = side(r.dst_address, r.dst_networkconf_id, r.dst_firewallgroup_ids);
  const port = r.dst_port ? `:${r.dst_port}` : '';
  const off = r.enabled ? '' : ' (disabled)';
  return `${r.ruleset} #${r.rule_index}: ${r.action.toUpperCase()} ${r.protocol ?? 'all'} ${src} → ${dst}${port} "${r.name}"${off}`;
}

/** Every `networkIds` array inside a traffic filter, whatever its exact shape. */
function filterNetworkIds(filter: unknown, found: string[] = []): string[] {
  if (Array.isArray(filter)) filter.forEach((f) => filterNetworkIds(f, found));
  else if (filter && typeof filter === 'object') {
    for (const [k, v] of Object.entries(filter)) {
      if (k === 'networkIds' && Array.isArray(v))
        found.push(...v.filter((x): x is string => typeof x === 'string'));
      else filterNetworkIds(v, found);
    }
  }
  return found;
}

/** `IoT → Default: BLOCK all "name"`: networks when the side filters on them, else the zone. */
function policyLine(
  p: FirewallPolicy,
  zones: Map<string, FirewallZone>,
  networkName: (id: string) => string | undefined,
) {
  const side = (s: FirewallPolicy['source']) => {
    const zone = zones.get(s?.zoneId ?? '')?.name ?? 'any zone';
    if (!s?.trafficFilter) return zone;
    const nets = filterNetworkIds(s.trafficFilter).map((id) => networkName(id) ?? id);
    if (nets.length) return nets.join(', ');
    const type = (s.trafficFilter as { type?: unknown }).type;
    return `${zone} [${typeof type === 'string' ? type.toLowerCase() : 'filtered'}]`;
  };
  const what = p.ipProtocolScope?.protocolFilter ? 'filtered protocols' : 'all';
  const off = p.enabled === false ? ' (disabled)' : '';
  return `${side(p.source)} → ${side(p.destination)}: ${p.action?.type ?? '?'} ${what}${p.name ? ` "${p.name}"` : ''}${off}`;
}

function wifiSecurity(w: WlanConf): string {
  if (w.security === 'open') return 'open';
  const enterprise = w.security === 'wpaeap' ? ' Enterprise' : '';
  if (w.wpa3_support && w.wpa3_transition) return `WPA2/WPA3${enterprise}`;
  if (w.wpa3_support) return `WPA3${enterprise}`;
  if (w.wpa_mode === 'wpa2') return `WPA2${enterprise}`;
  return `${w.security}${w.wpa_mode ? ` ${w.wpa_mode}` : ''}`;
}

const namesOf = (networks: NetworkConf[]) => {
  const byId = new Map(networks.map((n) => [n._id, n.name]));
  return (id: string) => byId.get(id);
};

export function createSecurityTools(deps: ReadDeps): ToolDefinition[] {
  const { official, legacy, syslog, sites } = deps;
  const now = deps.now ?? Date.now;

  return [
    defineTool({
      name: 'unifi_posture_audit',
      description:
        'Audit the security posture and list findings (severity, object, why), HIGH first: port forwards open to any source with the inbound threats against their target; WiFi with no encryption, WPA2-only where an AP supports WPA3, or a guest SSID not isolated; zone policies that let a less trusted zone into a more trusted one; ALLOW policies matching any → any; IDS/IPS off or detect-only; clients first seen in the last newClientDays; devices with firmware updates. Rules that cannot run (e.g. zone rules while Zone-Based Firewall is off) are listed under skipped with the reason. WPS is not checked: the console config does not expose it.',
      inputSchema: {
        site: siteInput,
        newClientDays: z
          .number()
          .int()
          .min(1)
          .max(90)
          .default(7)
          .describe('Window for new clients, in days (default 7)'),
        threatDays: z
          .number()
          .int()
          .min(1)
          .max(30)
          .default(7)
          .describe('Window for inbound threats against port-forward targets, in days (default 7)'),
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        const input = await loadPostureInput(deps, site, {
          newClientDays: a.newClientDays,
          threatDays: a.threatDays,
        });
        const findings = auditPosture(input);
        const skipped = skippedRules(input);
        const count = (s: string) => findings.filter((f) => f.severity === s).length;
        return compact({
          site: site.name,
          counts: { HIGH: count('HIGH'), MEDIUM: count('MEDIUM'), LOW: count('LOW') },
          findings,
          skipped: skipped.length ? skipped : undefined,
          threatScan:
            input.threats.truncatedAt === undefined
              ? undefined
              : coverageNote(input.threats.truncatedAt),
        });
      },
    }),

    defineTool({
      name: 'unifi_list_firewall',
      description:
        'The firewall as readable one-line rules ("IoT → Default: BLOCK all"): zones and zone policies, ACL rules, DNS policies and traffic matching lists. While Zone-Based Firewall is off, says so and lists the old-style rules instead, read-only.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [networks, officialNets, acl, dns, traffic] = await Promise.all([
          legacy.networkConf(site.ref),
          official.listNetworks(site.id),
          official.listAcl(site.id),
          official.listDnsPolicies(site.id),
          official.listTrafficLists(site.id),
        ]);
        const legacyName = namesOf(networks);
        const officialName = new Map(officialNets.map((n) => [n.id, n.name]));
        const networkName = (id: string) => officialName.get(id) ?? legacyName(id);
        const others = {
          aclRules: acl.map((x) => x.name ?? x.id),
          dnsPolicies: dns.map((x) => x.domain ?? x.id),
          trafficMatchingLists: traffic.map((x) => x.name ?? x.id),
        };
        try {
          const [zones, policies] = await Promise.all([
            official.listFirewallZones(site.id),
            official.listFirewallPolicies(site.id),
          ]);
          const byId = new Map(zones.map((z) => [z.id, z]));
          return {
            site: site.name,
            zones: zones.map(
              (z) =>
                `${z.name ?? z.id}: ${(z.networkIds ?? []).map(networkName).join(', ') || '(no networks)'}`,
            ),
            policies: policies.map((p) => policyLine(p, byId, networkName)),
            ...others,
          };
        } catch (error) {
          if (!(error instanceof UnifiApiError && error.kind === 'zbf-disabled')) throw error;
          const rules = await legacy.firewallRules(site.ref);
          return {
            site: site.name,
            zoneBasedFirewall: error.message,
            legacy: {
              label: LEGACY_RULES_LABEL,
              rules: rules.map((r) => legacyRuleLine(r, legacyName)),
            },
            ...others,
          };
        }
      },
    }),

    defineTool({
      name: 'unifi_list_port_forwards',
      description:
        'Port forwards as one line each ("Synology: WAN 61119 → 192.168.10.3:6690 tcp_udp from any"), whether enabled, and the client behind the LAN address (matched by IP).',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [forwards, clients] = await Promise.all([
          legacy.portForwards(site.ref),
          legacy.knownClients(site.ref),
        ]);
        return {
          site: site.name,
          forwards: forwards.map((f) => {
            const lan = f.fwdPort && f.fwdPort !== f.dstPort ? `${f.fwd}:${f.fwdPort}` : f.fwd;
            return compact({
              id: f.id,
              rule: `${f.name}: WAN ${f.dstPort} → ${lan} ${f.proto} from ${f.src}`,
              enabled: f.enabled,
              target: clients.find((c) => c.ip === f.fwd)?.name,
            });
          }),
        };
      },
    }),

    defineTool({
      name: 'unifi_list_wifi',
      description:
        'WiFi networks (SSIDs): security (open, WPA2, WPA2/WPA3, WPA3), the network they bridge to, guest and client isolation, hidden, bands and PMF.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [wlans, networks] = await Promise.all([
          legacy.wlanConf(site.ref),
          legacy.networkConf(site.ref),
        ]);
        const networkName = namesOf(networks);
        return {
          site: site.name,
          wifi: wlans.map((w) =>
            compact({
              id: w._id,
              name: w.name,
              enabled: w.enabled,
              security: wifiSecurity(w),
              network: w.networkconf_id ? networkName(w.networkconf_id) : undefined,
              guest: w.is_guest || undefined,
              clientIsolation: w.l2_isolation || undefined,
              hidden: w.hide_ssid || undefined,
              bands: w.wlan_bands,
              pmf: w.pmf_mode,
            }),
          ),
        };
      },
    }),

    defineTool({
      name: 'unifi_list_networks',
      description:
        'Networks (LAN and WAN): name, official id and legacy id, purpose, VLAN, subnet, DHCP, isolation, internet access, and the WAN address.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        const [networks, officialNets] = await Promise.all([
          legacy.networkConf(site.ref),
          official.listNetworks(site.id),
        ]);
        return {
          site: site.name,
          networks: networks.map((n) => {
            const o = officialNets.find((x) => sameText(x.name, n.name));
            return compact({
              name: n.name,
              id: o?.id,
              legacyId: n._id,
              purpose: n.purpose,
              enabled: n.enabled ?? o?.enabled,
              vlan: o?.vlanId ?? (n.vlan_enabled || n.vlan !== undefined ? n.vlan : undefined),
              subnet: n.ip_subnet,
              dhcp: n.dhcpd_enabled,
              isolated: n.network_isolation_enabled,
              internetAccess: n.internet_access_enabled,
              wanIp: n.wan_ip,
            });
          }),
        };
      },
    }),

    defineTool({
      name: 'unifi_audit_log',
      description:
        "Who changed what and when: the console's AUDIT log (default last 7 days), newest first. actor filters to one admin by name or id; pass actor: 'unifi-mcp' to see only this MCP's own changes once its dedicated admin exists.",
      inputSchema: {
        site: siteInput,
        actor: z.string().min(1).optional().describe('Admin name or id to filter to'),
        since: sinceInput,
        until: untilInput,
        limit: limitInput(100, 1000),
      },
      annotations: READ,
      handler: async (a) => {
        const site = await sites.resolve(a.site);
        const range = parseRange(a.since, a.until, '7d', now());
        const scan = await syslog.scan(site.ref, {
          ...range,
          ceiling: EVENT_CEILING,
          filter: (e) =>
            e.category === 'AUDIT' &&
            (a.actor === undefined ||
              sameText(e.parameters.ADMIN?.name, a.actor) ||
              sameText(e.parameters.ADMIN?.id, a.actor)),
        });
        const newestFirst = [...scan.entries].sort((x, y) => y.timestamp - x.timestamp);
        const { rows, truncated } = cut(newestFirst, a.limit);
        return compact({
          site: site.name,
          range: { from: iso(range.from), to: iso(range.to) },
          total: scan.entries.length,
          entries: rows.map((e) =>
            compact({
              time: iso(e.timestamp),
              actor: e.parameters.ADMIN?.name ?? e.parameters.ADMIN?.id,
              action: e.title,
              message: renderMessage(e),
            }),
          ),
          truncated,
          scan: scan.truncatedAt === undefined ? undefined : coverageNote(scan.truncatedAt),
        });
      },
    }),
  ];
}
