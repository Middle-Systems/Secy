/**
 * Typed fetch wrapper for the Secy backend.
 *
 * Every path is relative to `API_BASE` ('/api'), which the Vite dev server
 * proxies to the Spring Boot app with the `/api` prefix stripped (see
 * `vite.config.ts`). In production the same prefix is expected to be routed to
 * the backend by whatever serves the built assets.
 *
 * The feed ingest endpoints (`/kev/ingest`, `/epss/ingest`, `/nvd/ingest`) are
 * `POST` and answer 202 with a `Job` to poll — they no longer block for the
 * download. `DELETE /products/:id` returns `void`, and
 * `/sbom/:id/vulnerabilities` returns a bare 204 when there is nothing to
 * report — so an empty body is a valid success and is surfaced as `undefined`
 * rather than a JSON parse error.
 */

export const API_BASE = '/api';

/* -------------------------------------------------------------------------- */
/* Auth                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The bearer token for outgoing requests.
 *
 * Held in a module variable rather than read from `localStorage` per request:
 * `AuthProvider` is the single owner of the session and pushes the token here
 * with `setAuthToken()`, so there is exactly one place that decides what
 * "signed in" means, and storage stays an implementation detail of the provider.
 */
let authToken: string | null = null;

/** Set (or clear, with `null`) the token sent as `Authorization: Bearer`. */
export function setAuthToken(token: string | null): void {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

/** Called when the backend rejects a request from an apparently-signed-in caller. */
export type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

/**
 * Register the callback fired on a 401. `AuthProvider` uses it to drop the
 * session and send the user back to `/login`; pass `null` to unregister.
 */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

/**
 * `/auth/**` is exempt from the 401 handler: a rejected sign-in means "wrong
 * password", not "your session expired", and bouncing the user off the login
 * screen they are already on would be a loop. The login form reports those
 * itself.
 */
function shouldReportUnauthorized(path: string): boolean {
  return !path.replace(/^\//, '').startsWith('auth/');
}

/** Error thrown for any non-2xx response. */
export class ApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  /** Parsed JSON body, or the raw text, when the server sent one. */
  readonly body: unknown;

  constructor(response: Response, body: unknown) {
    const detail =
      typeof body === 'object' && body !== null && 'message' in body
        ? String((body as { message: unknown }).message)
        : response.statusText;
    super(`${response.status} ${detail} (${response.url})`);
    this.name = 'ApiError';
    this.status = response.status;
    this.statusText = response.statusText;
    this.url = response.url;
    this.body = body;
  }
}

/** Values accepted in a query string; `undefined`/`null` entries are dropped. */
export type QueryValue = string | number | boolean | undefined | null;

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  /** Appended as a query string; empty-ish values are omitted. */
  query?: Record<string, QueryValue>;
  /** Serialized as JSON unless it is already a `BodyInit`. */
  body?: unknown;
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const url = `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
  if (!query) return url;

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

async function parseBody(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205) return undefined;

  const text = await response.text();
  if (!text) return undefined;

  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return JSON.parse(text) as unknown;
  }
  return text;
}

/**
 * Perform a request against the API.
 *
 * `T` is the expected success payload. Endpoints that legitimately return no
 * body should be called as `request<void>(...)`.
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { query, body, headers, ...init } = options;

  const isBodyInit =
    body instanceof FormData ||
    body instanceof Blob ||
    body instanceof URLSearchParams ||
    body instanceof ArrayBuffer ||
    typeof body === 'string';

  const response = await fetch(buildUrl(path, query), {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(body !== undefined && !isBodyInit ? { 'Content-Type': 'application/json' } : {}),
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : isBodyInit ? (body as BodyInit) : JSON.stringify(body),
  });

  const payload = await parseBody(response);

  if (!response.ok) {
    // A 401 while we believed we had a session means the token is gone or
    // expired; tell the provider before the caller sees the error, so the
    // redirect happens even for a rejection nobody catches.
    if (response.status === 401 && authToken && shouldReportUnauthorized(path)) {
      unauthorizedHandler?.();
    }
    throw new ApiError(response, payload);
  }

  return payload as T;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'GET' }),

  post: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'POST', body }),

  put: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'PUT', body }),

  patch: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'PATCH', body }),

  delete: <T = void>(path: string, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'DELETE' }),
};
