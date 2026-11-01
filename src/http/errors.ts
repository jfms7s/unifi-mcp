export type UnifiErrorKind =
  | 'unreachable'
  | 'status'
  | 'endpoint-changed'
  | 'certificate-changed'
  | 'timeout'
  | 'zbf-disabled';

export interface UnifiApiErrorOptions {
  kind: UnifiErrorKind;
  method: string;
  path: string;
  status?: number;
  detail: string;
  /** Configured base URL, named only when the connection never landed. */
  baseUrl?: string;
}

/** Drops any userinfo before a base URL goes into a message; an unparseable URL is dropped entirely. */
function safeBaseUrl(baseUrl: string): string | undefined {
  try {
    const url = new URL(baseUrl);
    if (!url.username && !url.password) return baseUrl;
    url.username = '';
    url.password = '';
    return url.toString().replace(/\/$/, '');
  } catch {
    return undefined;
  }
}

function formatMessage({
  kind,
  method,
  path,
  status,
  detail,
  baseUrl,
}: UnifiApiErrorOptions): string {
  switch (kind) {
    case 'unreachable': {
      // The URL only helps when the request never arrived.
      const at = baseUrl === undefined ? undefined : safeBaseUrl(baseUrl);
      const target = at === undefined ? 'UniFi' : `UniFi at ${at}`;
      return `Cannot reach ${target} for ${method} ${path}: ${detail}`;
    }
    case 'status':
      return `UniFi returned ${status ?? 'an error'} for ${method} ${path}: ${detail}`;
    case 'timeout':
      return `UniFi timed out on ${method} ${path}: ${detail}`;
    case 'endpoint-changed':
      return `UniFi endpoint changed for ${method} ${path}: ${detail}`;
    case 'certificate-changed':
    case 'zbf-disabled':
      // These already say exactly what is wrong and what to do.
      return detail;
  }
}

export class UnifiApiError extends Error {
  readonly kind: UnifiErrorKind;
  readonly method: string;
  readonly path: string;
  readonly status?: number;
  readonly detail: string;

  constructor(options: UnifiApiErrorOptions) {
    super(formatMessage(options));
    this.name = 'UnifiApiError';
    this.kind = options.kind;
    this.method = options.method;
    this.path = options.path;
    this.status = options.status;
    this.detail = options.detail;
  }
}

export function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export function hasStatus(error: unknown, status: number): boolean {
  return error instanceof UnifiApiError && error.status === status;
}
