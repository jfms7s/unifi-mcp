import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { createOfficialApi, type OfficialApi } from '../../src/unifi/official.js';
import { liveFixture } from '../fixtures/live.js';
import { OFFICIAL, SITE_ID, failure, testClient, useServer } from './helpers.js';

const server = useServer();
const official = (): OfficialApi => createOfficialApi(testClient());
const S = `${OFFICIAL}/sites/${SITE_ID}`;

interface Page {
  data: Record<string, unknown>[];
  totalCount: number;
}

const lists: [
  name: string,
  url: string,
  fixture: string,
  call: (a: OfficialApi) => Promise<unknown[]>,
][] = [
  ['listDevices', `${S}/devices`, 'official-devices', (a) => a.listDevices(SITE_ID)],
  ['listClients', `${S}/clients`, 'official-clients', (a) => a.listClients(SITE_ID)],
  ['listNetworks', `${S}/networks`, 'official-networks', (a) => a.listNetworks(SITE_ID)],
  ['listWifi', `${S}/wifi/broadcasts`, 'official-wifi-broadcasts', (a) => a.listWifi(SITE_ID)],
  ['listWans', `${S}/wans`, 'official-wans', (a) => a.listWans(SITE_ID)],
  ['listVpnServers', `${S}/vpn/servers`, 'official-vpn-servers', (a) => a.listVpnServers(SITE_ID)],
  [
    'listS2sTunnels',
    `${S}/vpn/site-to-site-tunnels`,
    'official-vpn-site-to-site-tunnels',
    (a) => a.listS2sTunnels(SITE_ID),
  ],
  [
    'listDpiCategories',
    `${OFFICIAL}/dpi/categories`,
    'official-dpi-categories',
    (a) => a.listDpiCategories(),
  ],
  ['listAcl', `${S}/acl-rules`, 'official-acl-rules', (a) => a.listAcl(SITE_ID)],
  [
    'listDnsPolicies',
    `${S}/dns/policies`,
    'official-dns-policies',
    (a) => a.listDnsPolicies(SITE_ID),
  ],
  [
    'listTrafficLists',
    `${S}/traffic-matching-lists`,
    'official-traffic-matching-lists',
    (a) => a.listTrafficLists(SITE_ID),
  ],
];

describe('official list calls parse the live fixtures', () => {
  for (const [name, url, fixture, call] of lists) {
    it(name, async () => {
      server.use(http.get(url, () => HttpResponse.json(liveFixture(fixture) as never)));
      const result = await call(official());
      expect(result).toHaveLength((liveFixture(fixture) as Page).data.length);
    });
  }

  it('listDpiApps reads the first page and stops when the next is empty', async () => {
    const offsets: string[] = [];
    server.use(
      http.get(`${OFFICIAL}/dpi/applications`, ({ request }) => {
        const offset = new URL(request.url).searchParams.get('offset')!;
        offsets.push(offset);
        const page = liveFixture('official-dpi-applications') as Page;
        return HttpResponse.json(offset === '0' ? page : { ...page, data: [], offset: 200 });
      }),
    );
    const apps = await official().listDpiApps();
    expect(apps).toHaveLength(200);
    expect(apps[0]).toEqual({ id: 3, name: 'ICQ' });
    expect(offsets).toEqual(['0', '200']);
  });

  it('deviceStats reads the latest statistics', async () => {
    server.use(
      http.get(`${S}/devices/dev-1/statistics/latest`, () =>
        HttpResponse.json(liveFixture('official-devices-statistics-latest') as never),
      ),
    );
    expect(await official().deviceStats(SITE_ID, 'dev-1')).toMatchObject({
      uptimeSec: 132293,
      cpuUtilizationPct: 43.7,
      memoryUtilizationPct: 66.9,
    });
  });

  it('firewallOrdering sends both zone ids', async () => {
    let query = '';
    server.use(
      http.get(`${S}/firewall/policies/ordering`, ({ request }) => {
        query = new URL(request.url).search;
        return HttpResponse.json({
          orderedFirewallPolicyIds: { beforeSystemDefined: ['a'], afterSystemDefined: [] },
        });
      }),
    );
    const ordering = await official().firewallOrdering(SITE_ID, {
      sourceZoneId: 'z1',
      destinationZoneId: 'z2',
    });
    expect(ordering.orderedFirewallPolicyIds.beforeSystemDefined).toEqual(['a']);
    expect(query).toBe('?sourceFirewallZoneId=z1&destinationFirewallZoneId=z2');
  });

  it('firewall calls name the Policy Engine when Zone-Based Firewall is off', async () => {
    const zbf = liveFixture('official-firewall-zbf-disabled') as { status: number; body: unknown };
    server.use(
      http.get(`${S}/firewall/zones`, () =>
        HttpResponse.json(zbf.body as never, { status: zbf.status }),
      ),
      http.get(`${S}/firewall/policies`, () =>
        HttpResponse.json(zbf.body as never, { status: zbf.status }),
      ),
    );
    for (const call of [
      (a: OfficialApi) => a.listFirewallZones(SITE_ID),
      (a: OfficialApi) => a.listFirewallPolicies(SITE_ID),
    ]) {
      const error = await failure(call(official()));
      expect(error.kind).toBe('zbf-disabled');
      expect(error.message).toContain('Settings → Policy Engine');
    }
  });
});

describe('firewall reads with Zone-Based Firewall on (the live capture)', () => {
  const page = (name: string) => liveFixture(name) as Page;
  const serve = (path: string, body: unknown) =>
    server.use(http.get(`${S}${path}`, () => HttpResponse.json(body as never)));

  it('zones: six system zones, Internal holding Default, IoT and pi-cluster', async () => {
    serve('/firewall/zones', page('official-firewall-zones'));
    const zones = await official().listFirewallZones(SITE_ID);
    expect(zones.map((z) => z.name)).toEqual([
      'Dmz',
      'Gateway',
      'External',
      'Hotspot',
      'Vpn',
      'Internal',
    ]);
    expect(zones.every((z) => z.metadata.origin === 'SYSTEM_DEFINED')).toBe(true);
    expect(zones.find((z) => z.name === 'Internal')!.networkIds).toEqual([
      '50edfc66-8b84-4f92-8753-9d69a080a695',
      'f1b4fdb6-c787-4421-92bb-56d55e0ea95a',
      '80ec407d-e455-4a87-8b26-846881ebf07f',
    ]);
  });

  it('policies: all 98, the 32 IPS auto-blocks without an id', async () => {
    serve('/firewall/policies', page('official-firewall-policies'));
    const policies = await official().listFirewallPolicies(SITE_ID);
    expect(policies).toHaveLength(98);
    const user = policies.filter((p) => p.metadata.origin === 'USER_DEFINED');
    expect(user).toHaveLength(32);
    expect(user.every((p) => p.id === undefined && p.name.startsWith('IPS Block Traffic'))).toBe(
      true,
    );
    expect(policies.filter((p) => p.id !== undefined)).toHaveLength(66);
  });

  it('ordering: an id-less policy is a null in the console answer, kept as null', async () => {
    const pairs = (
      liveFixture('official-firewall-policies-ordering') as {
        pairs: Array<{ sourceZoneId: string; destinationZoneId: string; ordering: unknown }>;
      }
    ).pairs;
    const extExt = pairs.find(
      (p) =>
        p.sourceZoneId === p.destinationZoneId &&
        p.sourceZoneId === 'c266752b-f8ea-4d9e-8dc9-3658eb20eb50',
    )!;
    serve('/firewall/policies/ordering', extExt.ordering);
    const ordering = await official().firewallOrdering(SITE_ID, extExt);
    expect(ordering.orderedFirewallPolicyIds.beforeSystemDefined).toEqual(Array(8).fill(null));
  });

  it('a policy missing a used field (metadata, action, a zone) is endpoint-changed', async () => {
    const [first] = page('official-firewall-policies').data;
    for (const drop of ['metadata', 'action', 'source', 'name', 'enabled']) {
      const row = { ...first! };
      delete row[drop];
      serve('/firewall/policies', { offset: 0, limit: 200, count: 1, totalCount: 1, data: [row] });
      const error = await failure(official().listFirewallPolicies(SITE_ID));
      expect(error.kind, drop).toBe('endpoint-changed');
    }
  });

  it('null filters read as absent (M8)', async () => {
    const [first] = page('official-firewall-policies').data;
    const row = { ...first!, source: { ...(first!.source as object), trafficFilter: null } };
    serve('/firewall/policies', { offset: 0, limit: 200, count: 1, totalCount: 1, data: [row] });
    const [p] = await official().listFirewallPolicies(SITE_ID);
    expect(p!.source.trafficFilter ?? undefined).toBeUndefined();
    const nested = {
      ...first!,
      destination: {
        zoneId: 'z',
        trafficFilter: {
          type: 'IP_ADDRESS',
          ipAddressFilter: {
            type: 'IP_ADDRESSES',
            matchOpposite: false,
            items: [{ type: 'IP_ADDRESS', value: '192.168.10.3' }],
          },
          portFilter: null,
        },
      },
    };
    serve('/firewall/policies', { offset: 0, limit: 200, count: 1, totalCount: 1, data: [nested] });
    expect(await official().listFirewallPolicies(SITE_ID)).toHaveLength(1);
    const acl = {
      id: 'a',
      name: 'r',
      type: 'IPV4',
      action: 'BLOCK',
      enabled: true,
      index: 0,
      sourceFilter: { type: 'NETWORKS', networkIds: ['n'], portFilter: null },
      destinationFilter: null,
      metadata: { origin: 'USER_DEFINED' },
    };
    serve('/acl-rules', { offset: 0, limit: 200, count: 1, totalCount: 1, data: [acl] });
    expect(await official().listAcl(SITE_ID)).toHaveLength(1);
  });

  it('a zone without networkIds or metadata is endpoint-changed', async () => {
    const [first] = page('official-firewall-zones').data;
    for (const drop of ['networkIds', 'metadata', 'id']) {
      const row = { ...first! };
      delete row[drop];
      serve('/firewall/zones', { offset: 0, limit: 200, count: 1, totalCount: 1, data: [row] });
      const error = await failure(official().listFirewallZones(SITE_ID));
      expect(error.kind, drop).toBe('endpoint-changed');
    }
  });
});

describe('official paging', () => {
  const clients = (liveFixture('official-clients') as Page).data;
  const all = Array.from({ length: 250 }, (_, i) => ({
    ...clients[i % clients.length]!,
    id: `client-${i}`,
  }));

  it('listClients follows offset and limit across two pages', async () => {
    const seen: { offset: string | null; limit: string | null }[] = [];
    server.use(
      http.get(`${S}/clients`, ({ request }) => {
        const params = new URL(request.url).searchParams;
        seen.push({ offset: params.get('offset'), limit: params.get('limit') });
        const offset = Number(params.get('offset'));
        const data = all.slice(offset, offset + 200);
        return HttpResponse.json({ offset, limit: 200, count: data.length, totalCount: 250, data });
      }),
    );
    const result = await official().listClients(SITE_ID);
    expect(result).toHaveLength(250);
    expect(result.map((c) => c.id)).toEqual(all.map((c) => c.id));
    expect(seen).toEqual([
      { offset: '0', limit: '200' },
      { offset: '200', limit: '200' },
    ]);
  });
});

describe('official shape changes', () => {
  it('a client list missing a used field is an endpoint change naming the path', async () => {
    const page = structuredClone(liveFixture('official-clients')) as Page;
    delete page.data[0]!.type;
    server.use(http.get(`${S}/clients`, () => HttpResponse.json(page as never)));
    const error = await failure(official().listClients(SITE_ID));
    expect(error.kind).toBe('endpoint-changed');
    expect(error.message).toContain(`/v1/sites/${SITE_ID}/clients`);
  });
});
