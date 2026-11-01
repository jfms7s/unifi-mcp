import { describe, expect, it } from 'vitest';
import { groupPolicies } from '../../src/unifi/firewall-view.js';

const base = {
  name: 'p',
  enabled: true,
  action: { type: 'ALLOW', allowReturnTraffic: false },
  source: { zoneId: 'a' },
  destination: { zoneId: 'b' },
  ipProtocolScope: { ipVersion: 'IPV4' },
  loggingEnabled: false,
  metadata: { origin: 'USER_DEFINED' },
};

describe('groupPolicies collapses only truly identical rules (M7)', () => {
  it('the same rule in another zone pair collapses', () => {
    expect(groupPolicies([base, { ...base, source: { zoneId: 'c' } }])).toHaveLength(1);
  });

  it.each([
    ['schedule', { schedule: { mode: 'EVERY_DAY' } }],
    ['description', { description: 'other' }],
    ['ipsecFilter', { ipsecFilter: 'MATCH_ENCRYPTED' }],
    ['allowReturnTraffic', { action: { type: 'ALLOW', allowReturnTraffic: true } }],
    ['loggingEnabled', { loggingEnabled: true }],
  ])('a different %s keeps them apart', (_, change) => {
    expect(groupPolicies([base, { ...base, source: { zoneId: 'c' }, ...change }])).toHaveLength(2);
  });
});
