import { z } from 'zod';
import { UnifiApiError } from '../http/errors.js';
import { defineTool, type ToolDefinition } from '../mcp/types.js';
import { limitInput, parseRange, siteInput, sinceInput, untilInput } from './inputs.js';
import {
  dnsRecord,
  groupPolicies,
  pairsOf,
  policyMatch,
  type FirewallNames,
} from './firewall-view.js';
import type { FirewallRule, NetworkConf, WlanConf } from './legacy.js';
import { sameText } from './lookup.js';
import type { AclRule, FirewallPolicy, FirewallZone, TrafficList } from './official.js';
import { applyAccepted, auditPosture, loadPostureInput, skippedRules } from './posture.js';
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

/**
 * Policies as compact rows, the same rule in several zone pairs as one row
 * listing the pairs: `Internal → External, Vpn → External: BLOCK from X to Y "name"`.
 */
function policyRows(policies: FirewallPolicy[], names: FirewallNames): string[] {
  return groupPolicies(policies).map((g) => {
    const p = g[0]!;
    const off = p.enabled ? '' : ' (disabled)';
    const system = p.metadata.origin === 'SYSTEM_DEFINED' ? ' (system)' : '';
    const times = g.length > pairsOf(g, names).length ? ` ×${g.length}` : '';
    return `${pairsOf(g, names).join(', ')}: ${policyMatch(p, names)}${off}${system}${times}`;
  });
}

/** How many user-defined policies are copies of one another, said once. */
function duplicateNote(policies: FirewallPolicy[], names: FirewallNames): string | undefined {
  const groups = groupPolicies(policies.filter((p) => p.metadata.origin === 'USER_DEFINED')).filter(
    (g) => g.length > 1,
  );
  if (groups.length === 0) return undefined;
  const total = groups.reduce((n, g) => n + g.length, 0);
  const sizes = new Set(groups.map((g) => g.length));
  const spread = groups.every((g) => pairsOf(g, names).length === g.length);
  const each =
    sizes.size === 1 && spread
      ? `each repeated in ${[...sizes][0]} zone pairs`
      : `repeated up to ${Math.max(...sizes)} times`;
  const ips = groups.every((g) => g.every((p) => p.id === undefined))
    ? 'the IPS auto-blocks; '
    : '';
  return `${total} user-defined policies are ${groups.length} rules, ${each} (${ips}see unifi_posture_audit duplicate-policies)`;
}

const aclEndpoint = (e: AclRule['sourceFilter'], names: FirewallNames) => {
  if (!e) return 'any';
  const what =
    e.networkIds?.map((id) => names.network(id) ?? id).join(', ') ??
    e.ipAddressesOrSubnets?.join(',') ??
    e.macAddresses?.join(',') ??
    e.type.toLowerCase();
  return e.portFilter?.length ? `${what} port ${e.portFilter.join(',')}` : what;
};

const aclRow = (r: AclRule, names: FirewallNames) =>
  `${r.name}: ${r.action} ${aclEndpoint(r.sourceFilter, names)} → ${aclEndpoint(r.destinationFilter, names)}${r.enabled ? '' : ' (disabled)'}`;

const listRow = (l: TrafficList) =>
  `${l.name} (${l.type}): ${l.items.map((i) => String(i.value ?? `${String(i.start)}–${String(i.stop)}`)).join(', ')}`;

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
        'Audit the security posture and list findings (severity, object, why), HIGH first: port forwards open to any source with the inbound threats against their target; WiFi with no encryption, WPA2-only where an AP supports WPA3, or a guest SSID not isolated; zone policies that let a less trusted zone or network into a more trusted one; ALLOW policies matching any → any; networks of different trust sharing one zone (IoT in Internal); user-defined policies repeated as copies; IDS/IPS off or detect-only; clients first seen in the last newClientDays; devices with firmware updates. Rules that cannot run (e.g. zone rules while Zone-Based Firewall is off or a firewall endpoint changed) are listed under skipped with the reason. Findings the owner accepted as intended (UNIFI_MCP_ACCEPTED_FINDINGS) are listed under accepted, severity kept, and left out of counts; an acceptance that matches no finding is listed under staleAccepted. WPS is not checked: the console config does not expose it.',
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
        const skipped = skippedRules(input);
        const { findings, accepted, stale } = applyAccepted(
          auditPosture(input),
          deps.acceptedFindings ?? [],
          skipped,
        );
        const count = (s: string) => findings.filter((f) => f.severity === s).length;
        return compact({
          site: site.name,
          counts: { HIGH: count('HIGH'), MEDIUM: count('MEDIUM'), LOW: count('LOW') },
          findings,
          accepted: accepted.length ? accepted : undefined,
          staleAccepted: stale.length
            ? stale.map((a) => ({
                ...a,
                note: 'UNIFI_MCP_ACCEPTED_FINDINGS names this, but no finding matches it; remove it or fix the name',
              }))
            : undefined,
          skipped: skipped.length ? skipped : undefined,
          note: 'note' in input.firewall ? input.firewall.note : undefined,
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
        'The firewall as readable one-line rules ("Internal → External: BLOCK from 192.168.1.10 to 203.0.113.1 \"name\""): zones with their networks, zone policies (UniFi\'s own tagged (system); the same rule in several zone pairs is one row listing the pairs, and duplicates says how many user-defined policies are copies), ACL rules, DNS policies and traffic matching lists. While Zone-Based Firewall is off, says so and lists the old-style rules instead, read-only. A collection whose endpoint changed (new firmware) is named under unavailable with the error; the rest are still listed.',
      inputSchema: { site: siteInput },
      annotations: READ,
      handler: async ({ site: wanted }) => {
        const site = await sites.resolve(wanted);
        // A collection whose endpoint moved (new firmware) is reported, not fatal.
        const unavailable: Record<string, string> = {};
        const settle = <T>(name: string, read: Promise<T>, fallback: T): Promise<T> =>
          read.catch((error: unknown) => {
            if (!(error instanceof UnifiApiError && error.kind === 'endpoint-changed')) throw error;
            unavailable[name] = error.message;
            return fallback;
          });
        const [networks, officialNets, wans, acl, dns, traffic] = await Promise.all([
          settle('legacyNetworks', legacy.networkConf(site.ref), []),
          settle('networks', official.listNetworks(site.id), []),
          settle('wans', official.listWans(site.id), []),
          settle('aclRules', official.listAcl(site.id), []),
          settle('dnsPolicies', official.listDnsPolicies(site.id), []),
          settle('trafficMatchingLists', official.listTrafficLists(site.id), []),
        ]);
        const legacyName = namesOf(networks);
        const officialName = new Map([...officialNets, ...wans].map((n) => [n.id, n.name]));
        const networkName = (id: string) => officialName.get(id) ?? legacyName(id);
        const names: FirewallNames = {
          // Until the zones are read (or when they are unavailable): a short id.
          zone: (id) => `zone ${id.slice(0, 8)}`,
          network: networkName,
          list: (id) => traffic.find((l) => l.id === id)?.name,
        };
        const others = () => ({
          aclRules: unavailable.aclRules ? undefined : acl.map((r) => aclRow(r, names)),
          dnsPolicies: unavailable.dnsPolicies
            ? undefined
            : dns.map((d) => `${dnsRecord(d)}${d.enabled ? '' : ' (disabled)'}`),
          trafficMatchingLists: unavailable.trafficMatchingLists ? undefined : traffic.map(listRow),
          unavailable: Object.keys(unavailable).length ? unavailable : undefined,
        });
        let zones: FirewallZone[] | undefined;
        let policies: FirewallPolicy[] | undefined;
        try {
          [zones, policies] = await Promise.all([
            settle('zones', official.listFirewallZones(site.id), undefined),
            settle('policies', official.listFirewallPolicies(site.id), undefined),
          ]);
        } catch (error) {
          if (!(error instanceof UnifiApiError && error.kind === 'zbf-disabled')) throw error;
          const rules = await legacy.firewallRules(site.ref);
          return compact({
            site: site.name,
            zoneBasedFirewall: error.message,
            legacy: {
              label: LEGACY_RULES_LABEL,
              rules: rules.map((r) => legacyRuleLine(r, legacyName)),
            },
            ...others(),
          });
        }
        const zoneList = zones;
        if (zoneList) names.zone = (id) => zoneList.find((z) => z.id === id)?.name;
        return compact({
          site: site.name,
          zones: zoneList?.map(
            (z) =>
              `${z.name}: ${z.networkIds.map((id) => networkName(id) ?? id).join(', ') || '(no networks)'}`,
          ),
          policies: policies && policyRows(policies, names),
          duplicates: policies && duplicateNote(policies, names),
          ...others(),
        });
      },
    }),

    defineTool({
      name: 'unifi_list_port_forwards',
      description:
        'Port forwards as one line each ("NAS: WAN 8443 → 192.168.1.10:443 tcp from any"), whether enabled, and the client behind the LAN address (matched by IP).',
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
