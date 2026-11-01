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
    const zbf = liveFixture('official-firewall-zones') as { status: number; body: unknown };
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
