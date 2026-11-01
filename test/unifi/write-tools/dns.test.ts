import { describe, expect, it } from 'vitest';
import { connect, expectRejectsLooseConfirm } from '../../helpers/sdk.js';
import { useServer } from '../helpers.js';
import { dnsPolicies } from './firewall-fixtures.js';
import { without } from './firewall-fixtures.js';
import { OFFICIAL_SITE, fakeWriteConsole, type ConsoleOptions } from './harness.js';

const server = useServer();
const setup = (opts?: ConsoleOptions) => fakeWriteConsole(server, opts);
type Out = Record<string, unknown>;

const DNS = `${OFFICIAL_SITE}/dns/policies`;
const RECORD = {
  id: '77777777-0000-4000-8000-000000000001',
  type: 'A_RECORD',
  enabled: true,
  domain: 'nas.home.arpa',
  ipv4Address: '192.168.10.3',
  ttlSeconds: 3600,
  metadata: { origin: 'USER_DEFINED' },
};
const withRecord = { fixtures: { 'official-dns-policies': dnsPolicies(RECORD) } };

describe('DNS policies', () => {
  it('create is easy: one POST of the record', async () => {
    const { call, writes } = setup({ officialReply: { id: RECORD.id } });
    const out = await call('unifi_create_dns_policy', {
      type: 'A_RECORD',
      domain: 'nas.home.arpa',
      ipv4Address: '192.168.10.3',
      ttlSeconds: 3600,
    });
    expect(writes).toEqual([
      {
        method: 'POST',
        path: DNS,
        body: {
          type: 'A_RECORD',
          enabled: true,
          domain: 'nas.home.arpa',
          ipv4Address: '192.168.10.3',
          ttlSeconds: 3600,
        },
      },
    ]);
    expect(out).toEqual({
      changed: 'created',
      dnsPolicy: { id: RECORD.id, record: 'A_RECORD nas.home.arpa → 192.168.10.3' },
    });
  });

  it('update is confirm-level, found by domain, and PUTs the merged record', async () => {
    const { call, writes } = setup(withRecord);
    const preview = (await call('unifi_update_dns_policy', {
      dnsPolicy: 'nas.home.arpa',
      ipv4Address: '192.168.10.4',
    })) as Out;
    expect(preview).toEqual({
      preview: {
        would: 'update DNS policy',
        dnsPolicy: 'A_RECORD nas.home.arpa → 192.168.10.3',
        changes: { ipv4Address: { before: '192.168.10.3', after: '192.168.10.4' } },
      },
      requires: 'confirm: true',
    });
    await call('unifi_update_dns_policy', {
      dnsPolicy: RECORD.id,
      ipv4Address: '192.168.10.4',
      confirm: true,
    });
    const rest = without(RECORD, 'id', 'metadata');
    expect(writes).toEqual([
      {
        method: 'PUT',
        path: `${DNS}/${RECORD.id}`,
        body: { ...rest, ipv4Address: '192.168.10.4' },
      },
    ]);
  });

  it('delete is confirm-level', async () => {
    const { call, writes } = setup(withRecord);
    expect(
      ((await call('unifi_delete_dns_policy', { dnsPolicy: 'nas.home.arpa' })) as Out).requires,
    ).toBe('confirm: true');
    await call('unifi_delete_dns_policy', { dnsPolicy: 'nas.home.arpa', confirm: true });
    expect(writes).toEqual([{ method: 'DELETE', path: `${DNS}/${RECORD.id}`, body: undefined }]);
  });

  it('several records for one domain are candidates, never a guess', async () => {
    const aaaa = {
      ...RECORD,
      id: '77777777-0000-4000-8000-000000000002',
      type: 'AAAA_RECORD',
      ipv6Address: '2001:db8::3',
    };
    const { call, writes } = setup({
      fixtures: { 'official-dns-policies': dnsPolicies(RECORD, aaaa) },
    });
    const out = (await call('unifi_delete_dns_policy', {
      dnsPolicy: 'nas.home.arpa',
      confirm: true,
    })) as Out;
    expect(out).toMatchObject({ ambiguous: true });
    expect(out.candidates).toEqual([
      { id: RECORD.id, record: 'A_RECORD nas.home.arpa → 192.168.10.3' },
      { id: aaaa.id, record: 'AAAA_RECORD nas.home.arpa → 2001:db8::3' },
    ]);
    expect(writes).toEqual([]);
  });

  it.each([
    ['unifi_update_dns_policy', { dnsPolicy: 'nas.home.arpa', enabled: false }],
    ['unifi_delete_dns_policy', { dnsPolicy: 'nas.home.arpa' }],
  ] as const)('%s refuses every loose confirm through the SDK', async (name, args) => {
    const { tools, onWrite } = setup(withRecord);
    await expectRejectsLooseConfirm(await connect(tools), name, args, onWrite);
  });
});
