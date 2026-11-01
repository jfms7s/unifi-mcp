import { describe, expect, it } from 'vitest';
import { createScrubMap, prime, scrub } from '../scripts/scrub.js';

// Every value here is made up: this file is public, like the fixtures.

describe('scrub: MAC addresses', () => {
  it('maps MACs to stable 02:00:00:00:00:NN fakes, ignoring case, across files', () => {
    const map = createScrubMap();
    const a = scrub({ mac: 'a4:b1:c2:d3:e4:f5', other: 'A4:B1:C2:D3:E4:F6' }, map);
    const b = scrub({ macAddress: 'A4:B1:C2:D3:E4:F5' }, map);
    expect(a).toEqual({ mac: '02:00:00:00:00:01', other: '02:00:00:00:00:02' });
    expect(b).toEqual({ macAddress: '02:00:00:00:00:01' });
  });

  it('replaces MACs inside text and nested arrays', () => {
    const map = createScrubMap();
    expect(scrub(['seen a4:b1:c2:d3:e4:f5 twice', { list: ['a4:b1:c2:d3:e4:f5'] }], map)).toEqual([
      'seen 02:00:00:00:00:01 twice',
      { list: ['02:00:00:00:00:01'] },
    ]);
  });

  it('replaces the compact form of a known MAC, such as a serial or a host id prefix', () => {
    const map = createScrubMap();
    const out = scrub({ mac: 'a4:b1:c2:d3:e4:f5', hardware: { mac: 'A4B1C2D3E4F5' } }, map);
    expect(out).toEqual({ mac: '02:00:00:00:00:01', hardware: { mac: '020000000001' } });
  });

  it('keeps fakes as they are, so scrubbing twice changes nothing', () => {
    const map = createScrubMap();
    const once = scrub({ mac: 'a4:b1:c2:d3:e4:f5', ip: '8.20.30.40' }, map);
    expect(scrub(once, map)).toEqual(once);
  });

  it('rewrites the MAC tail UniFi appends to a client name', () => {
    const map = createScrubMap();
    const out = scrub(
      { CLIENT: { id: 'a4:b1:c2:d3:e4:f5', name: 'alice-laptop e4:f5', hostname: 'alice-laptop' } },
      map,
    );
    expect(out).toEqual({
      CLIENT: { id: '02:00:00:00:00:01', name: 'client-1 00:01', hostname: 'client-1' },
    });
  });
});

describe('scrub: IP addresses', () => {
  it('maps public IPv4 to 203.0.113.N and keeps private, loopback and netmask values', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        wan: '8.20.30.40',
        again: '8.20.30.40',
        other: '45.6.7.8',
        lan: ['10.1.2.3', '172.16.5.4', '192.168.10.1', '127.0.0.1', '169.254.1.1', '100.64.1.1'],
        netmask: '255.255.255.0',
      },
      map,
    );
    expect(out).toEqual({
      wan: '203.0.113.1',
      again: '203.0.113.1',
      other: '203.0.113.2',
      lan: ['10.1.2.3', '172.16.5.4', '192.168.10.1', '127.0.0.1', '169.254.1.1', '100.64.1.1'],
      netmask: '255.255.255.0',
    });
  });

  it('replaces public IPv4 inside text and CIDRs, but not inside version strings', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        name: 'Block Traffic from 192.168.10.3 to 8.20.30.40',
        subnet: '45.6.7.0/24',
        udm_version: 'UDRULT.ipq5322.v5.1.34.4d109cd',
        build: '7.1.66.15766',
      },
      map,
    );
    expect(out).toEqual({
      name: 'Block Traffic from 192.168.10.3 to 203.0.113.1',
      subnet: '203.0.113.2/24',
      udm_version: 'UDRULT.ipq5322.v5.1.34.4d109cd',
      build: '7.1.66.15766',
    });
  });

  it('rewrites a public port-forward target: fwd is not a firmware field', () => {
    expect(scrub({ fwd: '8.20.30.40', fwd_port: '443' }, createScrubMap())).toEqual({
      fwd: '203.0.113.1',
      fwd_port: '443',
    });
  });

  it('keeps the well-known public resolvers', () => {
    expect(scrub({ dns: ['1.1.1.1', '8.8.8.8'] }, createScrubMap())).toEqual({
      dns: ['1.1.1.1', '8.8.8.8'],
    });
  });

  it('maps global IPv6 to 2001:db8:: fakes and keeps privacy link-locals', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        v6: '2a01:4f8:1c0c:abcd::1',
        prefix: '2a01:4f8:1c0c:ab00::/56',
        ll: 'fe80::1c8e:f05e:fa5b:1234',
        ula: 'fd12:3456:789a::1',
      },
      map,
    );
    expect(out).toEqual({
      v6: '2001:db8::1',
      prefix: '2001:db8::2/56',
      ll: 'fe80::1c8e:f05e:fa5b:1234',
      ula: 'fd12:3456:789a::1',
    });
  });

  it('maps EUI-64 link-locals, which embed a MAC, to fake link-locals', () => {
    const out = scrub({ ll: 'fe80::a6b1:c2ff:fed3:e4f5' }, createScrubMap());
    expect(out).toEqual({ ll: 'fe80::ff:fe00:1' });
  });
});

describe('scrub: names', () => {
  it('maps client names and hostnames to client-N, the same name to the same fake', () => {
    const map = createScrubMap();
    const users = scrub(
      [
        { mac: 'a4:b1:c2:d3:e4:01', name: 'Bobs Phone', hostname: 'bobs-phone' },
        { mac: 'a4:b1:c2:d3:e4:02', hostname: 'kitchen-tablet' },
      ],
      map,
    );
    const later = scrub({ SRC_CLIENT: { id: 'a4:b1:c2:d3:e4:02', name: 'kitchen-tablet' } }, map);
    expect(users).toEqual([
      { mac: '02:00:00:00:00:01', name: 'client-1', hostname: 'client-2' },
      { mac: '02:00:00:00:00:02', hostname: 'client-3' },
    ]);
    expect(later).toEqual({ SRC_CLIENT: { id: '02:00:00:00:00:02', name: 'client-3' } });
  });

  it('replaces a whole learned name even when it contains a MAC', () => {
    const out = scrub(
      [{ mac: 'a4:b1:c2:d3:e4:f5', hostname: 'vendor42-a4b1c2d3e4f5' }],
      createScrubMap(),
    );
    expect(out).toEqual([{ mac: '02:00:00:00:00:01', hostname: 'client-1' }]);
  });

  it('maps device names to device-N, including uplink names and port labels', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        devices: [{ macAddress: 'a4:b1:c2:d3:e4:01', model: 'U7', name: 'Hallway AP' }],
        sta: [{ mac: 'a4:b1:c2:d3:e4:02', last_uplink_name: 'Hallway AP' }],
        DEVICE_WITH_PORT: { id: 'a4:b1:c2:d3:e4:01', model: 'U7', name: 'Hallway AP Port 3' },
      },
      map,
    );
    expect(out).toEqual({
      devices: [{ macAddress: '02:00:00:00:00:01', model: 'U7', name: 'device-1' }],
      sta: [{ mac: '02:00:00:00:00:02', last_uplink_name: 'device-1' }],
      DEVICE_WITH_PORT: { id: '02:00:00:00:00:01', model: 'U7', name: 'device-1 Port 3' },
    });
  });

  it('keeps model and product names, even when a device is named after its model', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        devices: [{ macAddress: 'a4:b1:c2:d3:e4:01', model: 'U7 Lite', name: 'U7 Lite' }],
        sysinfo: { ubnt_device_type: 'UDRULT', hostname: 'Home-Gateway' },
        host: { hardware: { name: 'UniFi Cloud Gateway Ultra', firmwareVersion: '5.1.34' } },
      },
      map,
    );
    expect(out).toEqual({
      devices: [{ macAddress: '02:00:00:00:00:01', model: 'U7 Lite', name: 'device-1' }],
      sysinfo: { ubnt_device_type: 'UDRULT', hostname: 'device-2' },
      host: { hardware: { name: 'UniFi Cloud Gateway Ultra', firmwareVersion: '5.1.34' } },
    });
  });

  it('names the console Gateway CGU wherever its real name appears, in any file order', () => {
    const map = createScrubMap();
    const devices = {
      data: [
        { macAddress: 'a4:b1:c2:d3:e4:01', model: 'UCG Ultra', name: 'Home Router' },
        { macAddress: 'a4:b1:c2:d3:e4:02', model: 'U7 Lite', name: 'Hall AP' },
      ],
    };
    const sysinfo = {
      data: [{ ubnt_device_type: 'UDRULT', name: 'Home Router', hostname: 'Home-Router' }],
    };
    const log = {
      CONSOLE_NAME: { id: 'Home Router', name: 'Home Router' },
      DEVICE_WITH_PORT: { id: 'a4:b1:c2:d3:e4:01', model: 'UCG-Ultra', name: 'Home Router Port 2' },
    };
    const health = { gw_name: 'Home Router', last_uplink_name: 'Home Router' };
    for (const file of [devices, sysinfo, log, health]) prime(file, map);
    expect(scrub(devices, map)).toEqual({
      data: [
        { macAddress: '02:00:00:00:00:01', model: 'UCG Ultra', name: 'Gateway CGU' },
        { macAddress: '02:00:00:00:00:02', model: 'U7 Lite', name: 'device-2' },
      ],
    });
    expect(scrub(sysinfo, map)).toEqual({
      data: [{ ubnt_device_type: 'UDRULT', name: 'Gateway CGU', hostname: 'device-3' }],
    });
    expect(scrub(log, map)).toEqual({
      CONSOLE_NAME: { id: 'Gateway CGU', name: 'Gateway CGU' },
      DEVICE_WITH_PORT: { id: '02:00:00:00:00:01', model: 'UCG-Ultra', name: 'Gateway CGU Port 2' },
    });
    expect(scrub(health, map)).toEqual({ gw_name: 'Gateway CGU', last_uplink_name: 'Gateway CGU' });
  });

  it('keeps the allow-listed names the tests rely on', () => {
    const allowed = [
      'pi-cluster',
      'data-archive',
      'MAC Hub',
      'Gateway CGU',
      'Default',
      'IoT',
      'Synology',
    ];
    const map = createScrubMap();
    const out = scrub(
      allowed.map((name) => ({ mac: 'a4:b1:c2:d3:e4:f5', model: 'X', name, hostname: name })),
      map,
    );
    expect(out).toEqual(
      allowed.map((name) => ({ mac: '02:00:00:00:00:01', model: 'X', name, hostname: name })),
    );
    expect(
      scrub({ DST_CLIENT: { id: 'a4:b1:c2:d3:e4:f5', name: 'data-archive e4:f5' } }, map),
    ).toEqual({ DST_CLIENT: { id: '02:00:00:00:00:01', name: 'data-archive 00:01' } });
  });

  it('maps SSIDs to ssid-N, also where they turn up in text', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        wlan: [{ name: 'Smith Family', x_passphrase: 'hunter22', security: 'wpapsk' }],
        broadcast: { name: 'Smith Family Guest', securityConfiguration: { type: 'WPA2_PERSONAL' } },
        rogue: { bssid: 'a4:b1:c2:d3:e4:f5', essid: 'Neighbour 5G' },
        WLAN: { id: '6a0000000000000000000001', name: 'Smith Family' },
        OBJECT: { name: 'Smith Family Guest' },
      },
      map,
    );
    expect(out).toEqual({
      wlan: [{ name: 'ssid-1', x_passphrase: '<redacted>', security: 'wpapsk' }],
      broadcast: { name: 'ssid-2', securityConfiguration: { type: 'WPA2_PERSONAL' } },
      rogue: { bssid: '02:00:00:00:00:01', essid: 'ssid-3' },
      WLAN: { id: '6a0000000000000000000001', name: 'ssid-1' },
      OBJECT: { name: 'ssid-2' },
    });
  });

  it('keeps names that are not people, devices or SSIDs', () => {
    const value = {
      apps: [{ id: 5, name: 'YouTube' }],
      networks: [{ name: 'Default', vlan: 1 }],
      widgets: [{ name: 'wifi_channels' }],
    };
    expect(scrub(value, createScrubMap())).toEqual(value);
  });

  it('learns names from every file first when primed, so earlier files match later ones', () => {
    const map = createScrubMap();
    // OBJECT gives no hint of what the name is; only the client list does.
    const log = { OBJECT: { name: 'garage-cam' } };
    const users = [{ mac: 'a4:b1:c2:d3:e4:f5', name: 'garage-cam' }];
    prime(log, map);
    prime(users, map);
    expect(scrub(log, map)).toEqual({ OBJECT: { name: 'client-1' } });
  });
});

describe('scrub: secrets', () => {
  it('redacts x_passphrase and every other x_* field', () => {
    const out = scrub(
      {
        x_passphrase: 'hunter22',
        x_ssh_username: 'root',
        x_iapp_key: 'abc',
        nested: { x_secret: 's' },
      },
      createScrubMap(),
    );
    expect(out).toEqual({
      x_passphrase: '<redacted>',
      x_ssh_username: '<redacted>',
      x_iapp_key: '<redacted>',
      nested: { x_secret: '<redacted>' },
    });
  });

  it('redacts fields named like key, secret, password, token or psk, in any case', () => {
    const out = scrub(
      {
        apiKey: 'k1',
        public_key: 'k2',
        radius_secret: 's',
        adminPassword: 'p',
        utm_token: 't',
        psk: 'wifi',
        tokens: ['a', 'b'],
        enabled: true,
        group_rekey: 3600,
        x_port: 22,
      },
      createScrubMap(),
    );
    expect(out).toEqual({
      apiKey: '<redacted>',
      public_key: '<redacted>',
      radius_secret: '<redacted>',
      adminPassword: '<redacted>',
      utm_token: '<redacted>',
      psk: '<redacted>',
      tokens: ['<redacted>', '<redacted>'],
      enabled: true,
      group_rekey: 3600,
      x_port: '<redacted>',
    });
  });

  it('redacts the partial Teleport token an audit entry names', () => {
    const entry = {
      key: 'GENERATED',
      parameters: {
        OBJECT: { id: '6ae5cd41ea55640257049119', name: '... 9876' },
        SECTION: { id: 'TELEPORT_TOKEN' },
      },
    };
    expect(scrub(entry, createScrubMap())).toEqual({
      key: 'GENERATED',
      parameters: {
        OBJECT: { id: '6ae5cd41ea55640257049119', name: '<redacted>' },
        SECTION: { id: 'TELEPORT_TOKEN' },
      },
    });
  });

  it('keeps a plain `key` field: the system log and settings use it as an identifier', () => {
    const value = { key: 'THREAT_DETECTED_KNOWN_SOURCE_CLIENT', settings: [{ key: 'mgmt' }] };
    expect(scrub(value, createScrubMap())).toEqual(value);
  });
});

describe('scrub: owner, account and console identity', () => {
  it('maps emails to user-N@example.com and account names to user-N', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        userData: {
          email: 'someone@example.org',
          fullName: 'Pat Example',
          localId: '8d000000-0000-4000-8000-000000000123',
        },
        note: 'mail someone@example.org',
        ADMIN: { id: '690000000000000000000abc', name: 'Pat Example' },
      },
      map,
    );
    expect(out).toEqual({
      userData: {
        email: 'user-1@example.com',
        fullName: 'user-1',
        localId: '00000000-0000-4000-8000-000000000001',
      },
      note: '<redacted>',
      ADMIN: { id: '000000000000000000000002', name: 'user-1' },
    });
  });

  it('maps the cloud host id and anything containing it', () => {
    const map = createScrubMap();
    const hostId = 'A4B1C2D3E4F50000000008F8DEE7000000000973879A0000000067FB2EBB:1234567890';
    const out = scrub(
      { id: hostId, controller_uuid: hostId, hostId, nested: `host ${hostId} up` },
      map,
    );
    const fake = (out as { id: string }).id;
    expect(fake).not.toContain('A4B1C2');
    expect(out).toEqual({
      id: fake,
      controller_uuid: fake,
      hostId: fake,
      nested: `host ${fake} up`,
    });
  });

  it('maps serials and anonymous ids to same-shaped fakes', () => {
    const out = scrub(
      {
        serial: 'F09FC2AB12CD',
        serialno: 'f09fc2ab12ce',
        anonymous_device_id: '43f36d3b-74dd-486b-893b-81d913c525f3',
        anon_client_id: 'c08184e795ca2c29725553a38fb8073b',
        anonid: 'a0bb0cce-33de-4c0b-8542-80859e09f92a',
        hardwareId: 'd52943ce-1e7b-52e8-8415-8404691e3580',
        sso_app_id: 'ZrDx2odjwwMNGB2Vgh04',
      },
      createScrubMap(),
    );
    expect(out).toEqual({
      serial: '000000000001',
      serialno: '000000000002',
      anonymous_device_id: '00000000-0000-4000-8000-000000000003',
      anon_client_id: '00000000000000000000000000000004',
      anonid: '00000000-0000-4000-8000-000000000005',
      hardwareId: '00000000-0000-4000-8000-000000000006',
      sso_app_id: 'id-7',
    });
  });

  it('maps DDNS and per-console cloud hostnames, and redacts the location', () => {
    const map = createScrubMap();
    const out = scrub(
      {
        local_dns_record: 'nas.somebody.myds.me',
        text: 'open https://somebody.myds.me:5001/ now',
        directConnectDomain: 'a4b1c2d3e4f5abcdef.id.ui.direct',
        monitors: ['ping.ui.com', 'google.com'],
        location: { text: 'Some Town, Some Country', lat: 1.5, long: 2.5 },
      },
      map,
    );
    expect(out).toEqual({
      local_dns_record: 'host-1.example.net',
      text: 'open https://host-2.example.net:5001/ now',
      directConnectDomain: 'host-3.example.net',
      monitors: ['ping.ui.com', 'google.com'],
      location: { text: '<redacted>', lat: 0, long: 0 },
    });
  });

  it('leaves internal ids, numbers, booleans and null alone and does not mutate its input', () => {
    const value = {
      _id: '6ae63ecdea5564025704a2ff',
      site_id: '693862dc3ce34976d544de91',
      id: '88f7af54-98f8-306a-a1c7-c9349722b1f6',
      n: 3,
      ok: false,
      none: null,
      mac: 'a4:b1:c2:d3:e4:f5',
    };
    const copy = structuredClone(value);
    const out = scrub(value, createScrubMap());
    expect(value).toEqual(copy);
    expect(out).toEqual({ ...value, mac: '02:00:00:00:00:01' });
  });
});
