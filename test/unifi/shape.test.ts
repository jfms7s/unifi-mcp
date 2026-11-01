import { describe, expect, it } from 'vitest';
import { confirmInput, limitInput, parseRange, parseTime } from '../../src/unifi/inputs.js';
import { renderMessage } from '../../src/unifi/shape.js';
import type { SyslogEntry } from '../../src/unifi/syslog.js';

const NOW = Date.UTC(2026, 10, 1, 12, 0, 0);

function entry(messageTemplate: string, parameters: SyslogEntry['parameters']): SyslogEntry {
  return {
    id: 'e1',
    timestamp: NOW,
    category: 'SECURITY',
    severity: 'HIGH',
    key: 'K',
    title: 'T',
    messageTemplate,
    parameters,
  };
}

describe('renderMessage', () => {
  it('fills each placeholder with the parameter name', () => {
    const e = entry(
      'A network intrusion attempt from {SRC_IP} to {DST_CLIENT} has been detected.',
      {
        SRC_IP: { id: '203.0.113.6', name: '203.0.113.6' },
        DST_CLIENT: { id: '02:00:00:00:00:1a', name: 'data-archive' },
      },
    );
    expect(renderMessage(e)).toBe(
      'A network intrusion attempt from 203.0.113.6 to data-archive has been detected.',
    );
  });

  it('falls back to the id when the parameter has no name', () => {
    expect(renderMessage(entry('{WHO} left', { WHO: { id: '02:00:00:00:00:1a' } }))).toBe(
      '02:00:00:00:00:1a left',
    );
  });

  it('renders a missing parameter as {NAME?}', () => {
    expect(
      renderMessage(entry('from {SRC_IP} to {DST_CLIENT}', { DST_CLIENT: { name: 'x' } })),
    ).toBe('from {SRC_IP?} to x');
  });

  it('treats a parameter with neither name nor id as missing', () => {
    expect(renderMessage(entry('{A}', { A: {} }))).toBe('{A?}');
  });

  it('leaves text without placeholders alone', () => {
    expect(renderMessage(entry('Nothing here.', {}))).toBe('Nothing here.');
  });
});

describe('parseTime', () => {
  it('reads relative spans as ago', () => {
    expect(parseTime('90m', NOW)).toBe(NOW - 90 * 60_000);
    expect(parseTime('24h', NOW)).toBe(NOW - 24 * 3_600_000);
    expect(parseTime('7d', NOW)).toBe(NOW - 7 * 86_400_000);
    expect(parseTime('2w', NOW)).toBe(NOW - 14 * 86_400_000);
  });

  it('reads ISO timestamps', () => {
    expect(parseTime('2026-10-31T00:00:00Z', NOW)).toBe(Date.UTC(2026, 9, 31));
  });

  it('rejects anything else, naming the accepted forms', () => {
    expect(() => parseTime('yesterday', NOW)).toThrow(/ISO.*24h/);
    expect(() => parseTime('0h', NOW)).toThrow(/ISO.*24h/);
  });
});

describe('parseRange', () => {
  it('defaults to the span ending now', () => {
    expect(parseRange(undefined, undefined, '24h', NOW)).toEqual({
      from: NOW - 86_400_000,
      to: NOW,
    });
  });

  it('takes since and until independently', () => {
    expect(parseRange('7d', '1d', '24h', NOW)).toEqual({
      from: NOW - 7 * 86_400_000,
      to: NOW - 86_400_000,
    });
  });

  it('rejects a range that ends before it starts', () => {
    expect(() => parseRange('1d', '2d', '24h', NOW)).toThrow(/before/);
  });
});

describe('inputs', () => {
  it('limitInput defaults and caps', () => {
    const limit = limitInput(50, 500);
    expect(limit.parse(undefined)).toBe(50);
    expect(limit.parse(500)).toBe(500);
    expect(() => limit.parse(501)).toThrow();
    expect(() => limit.parse(0)).toThrow();
  });

  it('confirmInput accepts only true or nothing', () => {
    expect(confirmInput.parse(true)).toBe(true);
    expect(confirmInput.parse(undefined)).toBeUndefined();
    expect(() => confirmInput.parse(false)).toThrow();
    expect(() => confirmInput.parse('true')).toThrow();
    expect(() => confirmInput.parse(1)).toThrow();
  });
});
