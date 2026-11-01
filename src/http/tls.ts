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

const PLAIN_TCP_REFUSED = 'refusing a plain-TCP connection to a console with a pinned certificate';

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
      // Fail closed: a pin means nothing over plain TCP, and the API key would travel in cleartext.
      if (options.protocol !== 'https:') return callback(new Error(PLAIN_TCP_REFUSED), null);
      connector(options, (error, socket) => {
        if (error) return callback(error, null);
        if (!(socket instanceof TLSSocket)) {
          socket.destroy();
          return callback(new Error(PLAIN_TCP_REFUSED), null);
        }
        const actual = socket.getPeerCertificate().fingerprint256 ?? 'no certificate';
        if (actual === expected) return callback(null, socket);
        socket.destroy();
        callback(new PinnedCertificateMismatch(expected, actual), null);
      });
    },
  });
}
