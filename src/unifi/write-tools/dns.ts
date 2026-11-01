import { z } from 'zod';
import { defineTool, type ToolDefinition } from '../../mcp/types.js';
import { guarded } from '../guard.js';
import { confirmInput, siteInput } from '../inputs.js';
import { ambiguous, lookup, sameText } from '../lookup.js';
import type { DnsPolicy } from '../official.js';
import { dnsRecord } from '../firewall-view.js';
import { compact } from '../shape.js';
import type { Site } from '../sites.js';
import { partial, write, type WriteDeps } from './common.js';
import { mergeUpdate } from './firewall-common.js';
import type { Plain } from './objects.js';

export const DNS_READ_ONLY = ['id', 'metadata'] as const;

/** Every field of `Create or update DNS policy` across its types (A, AAAA, CNAME, MX, SRV, TXT, forward). */
const dnsFields = {
  enabled: z.boolean().describe('Whether the record is served'),
  domain: z.string().min(1).max(127).describe('The domain the record is for'),
  ipv4Address: z.string().describe('A_RECORD: the IPv4 address'),
  ipv6Address: z.string().describe('AAAA_RECORD: the IPv6 address'),
  targetDomain: z.string().describe('CNAME_RECORD: the target'),
  ipAddress: z.string().describe('FORWARD_DOMAIN: the DNS server to forward to'),
  mailServerDomain: z.string().describe('MX_RECORD: the mail server'),
  serverDomain: z.string().describe('SRV_RECORD: the server'),
  service: z.string().describe('SRV_RECORD: the service'),
  protocol: z.string().describe('SRV_RECORD: the protocol'),
  port: z.number().int().min(0).max(65535).describe('SRV_RECORD: the port'),
  priority: z.number().int().describe('MX/SRV_RECORD: the priority'),
  weight: z.number().int().describe('SRV_RECORD: the weight'),
  text: z.string().describe('TXT_RECORD: the text'),
  ttlSeconds: z.number().int().min(0).max(86400).describe('Time to live (A, AAAA, CNAME)'),
};
const TYPES = [
  'A_RECORD',
  'AAAA_RECORD',
  'CNAME_RECORD',
  'MX_RECORD',
  'SRV_RECORD',
  'TXT_RECORD',
  'FORWARD_DOMAIN',
] as const;

const policyInput = z.string().min(1).describe('DNS policy id, or its domain');

const bare = (domain: string) => domain.trim().toLowerCase().replace(/\.$/, '');

/**
 * Why a record can redirect unifi-mcp itself: it is for the console's own
 * hostname, or forwards that name (or a parent of it) to another server.
 */
export function consoleRedirect(
  record: { type?: unknown; domain?: unknown },
  host: string | undefined,
): string | undefined {
  if (host === undefined || typeof record.domain !== 'string') return undefined;
  const domain = bare(record.domain);
  if (domain === host) {
    return `the record is for ${host}, the console's hostname in UNIFI_URL, so it can send unifi-mcp elsewhere`;
  }
  if (record.type === 'FORWARD_DOMAIN' && host.endsWith(`.${domain}`)) {
    return `it forwards ${domain}, which holds ${host} (the console's hostname in UNIFI_URL), to another DNS server`;
  }
  return undefined;
}

async function findDns(deps: WriteDeps, site: Site, query: string) {
  const all = await deps.official.listDnsPolicies(site.id);
  const match = lookup(all, query, [(d, q) => sameText(d.id, q), (d, q) => sameText(d.domain, q)]);
  if ('ambiguous' in match)
    return ambiguous(query, match.ambiguous, (d: DnsPolicy) => ({
      id: d.id,
      record: dnsRecord(d),
    }));
  if ('none' in match) {
    const known = all.length
      ? `the records are: ${all.map(dnsRecord).join('; ')}`
      : 'the console has no DNS policies';
    throw new Error(`No DNS policy matches "${query}"; ${known}`);
  }
  return match.found;
}

export function createDnsWriteTools(deps: WriteDeps): ToolDefinition[] {
  return [
    defineTool({
      name: 'unifi_create_dns_policy',
      description:
        'Create a DNS policy (official POST /dns/policies): a local A, AAAA, CNAME, MX, SRV or TXT record, or a forward domain. Easy: DNS records do not filter traffic. When UNIFI_URL names the console by hostname, a record for that hostname, or a forward of it or a parent domain, can send unifi-mcp elsewhere, so it needs confirm: true and previews first.',
      inputSchema: {
        site: siteInput,
        type: z.enum(TYPES).describe('Record type'),
        ...partial(dnsFields),
        domain: dnsFields.domain,
        enabled: dnsFields.enabled.default(true),
        confirm: confirmInput,
      },
      annotations: write({ destructive: false, idempotent: false }),
      handler: async ({ site: wanted, confirm, ...a }) => {
        const site = await deps.sites.resolve(wanted);
        const body = compact(a as Plain);
        return guarded(
          {
            level: 'easy',
            reason: consoleRedirect(body, deps.consoleHost),
            confirm,
            preview: async () => ({ would: 'create DNS policy', dnsPolicy: body }),
            run: async () => {
              const id = await deps.official.createFirewallObject(site.id, 'dns', body);
              return { changed: 'created', dnsPolicy: { id, record: dnsRecord(body) } };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_update_dns_policy',
      description:
        "Change fields of a DNS policy (found by id or domain); the tool reads it, merges and PUTs the whole record. Its type can't change: delete and recreate. Always needs confirm: true; without it the tool previews the changed fields.",
      inputSchema: {
        site: siteInput,
        dnsPolicy: policyInput,
        ...partial(dnsFields),
        confirm: confirmInput,
      },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, dnsPolicy, confirm, ...patch }) => {
        const site = await deps.sites.resolve(wanted);
        const d = await findDns(deps, site, dnsPolicy);
        if ('ambiguous' in d) return d;
        const current = await deps.official.getFirewallObject(site.id, 'dns', d.id);
        const { body, changes } = mergeUpdate(current, compact(patch as Plain), DNS_READ_ONLY);
        const fields = Object.keys(changes);
        const record = dnsRecord(d);
        if (fields.length === 0) return { unchanged: true, dnsPolicy: record };
        return guarded(
          {
            level: 'confirm',
            reason: consoleRedirect(body, deps.consoleHost),
            confirm,
            preview: async () => ({ would: 'update DNS policy', dnsPolicy: record, changes }),
            run: async () => {
              await deps.official.updateFirewallObject(site.id, 'dns', d.id, body);
              return { changed: 'updated', dnsPolicy: dnsRecord(body), fields };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),

    defineTool({
      name: 'unifi_delete_dns_policy',
      description:
        'Delete a DNS policy (found by id or domain; several records for one domain come back as candidates). Always needs confirm: true; without it the tool previews.',
      inputSchema: { site: siteInput, dnsPolicy: policyInput, confirm: confirmInput },
      annotations: write({ destructive: true, idempotent: true }),
      handler: async ({ site: wanted, dnsPolicy, confirm }) => {
        const site = await deps.sites.resolve(wanted);
        const d = await findDns(deps, site, dnsPolicy);
        if ('ambiguous' in d) return d;
        const record = dnsRecord(d);
        return guarded(
          {
            level: 'confirm',
            confirm,
            preview: async () => ({ would: 'delete DNS policy', dnsPolicy: record }),
            run: async () => {
              await deps.official.deleteFirewallObject(site.id, 'dns', d.id);
              return { changed: 'deleted', dnsPolicy: record };
            },
          },
          await deps.scope(site),
          [],
        );
      },
    }),
  ];
}
