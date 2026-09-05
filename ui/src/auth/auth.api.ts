import { api } from '@/api/client';

import type { AuthConfig, AuthResponse, AuthUser, LoginPayload, RegisterPayload } from '@/auth/types';

/**
 * The `/auth/**` calls.
 *
 * These deliberately sit outside `src/api/queries.ts`: sessions are bootstrap
 * state, not server state — they are what decides whether the query client may
 * fetch at all, so putting them behind TanStack Query would invert the
 * dependency. They still go through `api` from `client.ts`, so base URL, JSON
 * handling and `ApiError` behave exactly as everywhere else.
 */
export const authApi = {
  login: (payload: LoginPayload) => api.post<AuthResponse>('/auth/login', payload),

  register: (payload: RegisterPayload) => api.post<AuthResponse>('/auth/register', payload),

  /** Validates the current token and returns the account behind it. */
  me: () => api.get<AuthUser>('/auth/me'),

  /** Anonymous: tells the login screen whether to offer registration. */
  config: () => api.get<AuthConfig>('/auth/config'),
};
