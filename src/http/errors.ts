export interface UnifiApiErrorOptions {
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

export class UnifiApiError extends Error {
  readonly method: string;
  readonly path: string;
  readonly status?: number;
  readonly detail: string;

  constructor(options: UnifiApiErrorOptions) {
    const { method, path, status, detail, baseUrl } = options;
    // The URL only helps when the request never arrived; once a status comes
    // back the server was plainly reachable.
    const at = baseUrl === undefined ? undefined : safeBaseUrl(baseUrl);
    const target = at === undefined ? 'UniFi' : `UniFi at ${at}`;
    const message =
      status === undefined
        ? `Cannot reach ${target} for ${method} ${path}: ${detail}`
        : `UniFi returned ${status} for ${method} ${path}: ${detail}`;
    super(message);
    this.name = 'UnifiApiError';
    this.method = method;
    this.path = path;
    this.status = status;
    this.detail = detail;
  }
}

export function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export function hasStatus(error: unknown, status: number): boolean {
  return error instanceof UnifiApiError && error.status === status;
}
