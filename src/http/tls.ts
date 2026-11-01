import { TLSSocket } from 'node:tls';
import { Agent, buildConnector, type Dispatcher } from 'undici';
import type { ConsoleConnection } from '../config.js';

/** Thrown from the connector when the console presents a certificate other than the pinned one. */
export class PinnedCertificateMismatch extends Error {
  readonly expected: string;
  readonly actual: string;

  constructor(expected: string, actual: string) {
    super(`console certificate changed: expected ${expected}, got ${actual}`);
    this.name = 'PinnedCertificateMismatch';
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * A dispatcher for the console only. UniFi consoles serve a self-signed
 * certificate for an IP, so the chain and the hostname are never checked; with
 * a fingerprint, the leaf certificate's SHA-256 must match it exactly.
 */
export function createConsoleDispatcher(tls: ConsoleConnection['tls']): Dispatcher {
  if ('insecure' in tls) return new Agent({ connect: { rejectUnauthorized: false } });

  const expected = tls.fingerprint;
  // No TLS session reuse: every connection shows its certificate afresh.
  const connector = buildConnector({ rejectUnauthorized: false, maxCachedSessions: 0 });

  return new Agent({
    connect(options, callback) {
      connector(options, (error, socket) => {
        if (error) return callback(error, null);
        // A plain http:// console has no certificate to pin.
        if (!(socket instanceof TLSSocket)) return callback(null, socket);
        const actual = socket.getPeerCertificate().fingerprint256 ?? 'no certificate';
        if (actual === expected) return callback(null, socket);
        socket.destroy();
        callback(new PinnedCertificateMismatch(expected, actual), null);
      });
    },
  });
}
