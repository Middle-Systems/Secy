import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import { setAuthToken, setUnauthorizedHandler } from '@/api/client';
import { AuthContext } from '@/auth/auth-context';
import { setAuthSnapshot } from '@/auth/auth-store';
import { authApi } from '@/auth/auth.api';
import { clearStoredToken, readStoredToken, writeStoredToken } from '@/auth/storage';
import type {
  AuthContextValue,
  AuthResponse,
  AuthStatus,
  AuthUser,
  LoginPayload,
  RegisterPayload,
} from '@/auth/types';

interface Session {
  status: AuthStatus;
  user: AuthUser | null;
  token: string | null;
}

const SIGNED_OUT: Session = { status: 'unauthenticated', user: null, token: null };

export interface AuthProviderProps {
  children: ReactNode;
  /**
   * Test seam. Supplying both starts the provider already authenticated and
   * skips the `/auth/me` hydration, so a component test never touches the
   * network. Production code always omits these.
   */
  initialUser?: AuthUser | null;
  initialToken?: string | null;
}

/**
 * Owns the session: the token, the account behind it, and the transitions
 * between signed in and signed out.
 *
 * It is mounted outside the router (see `main.tsx`) because the route guard
 * depends on it, not the other way round. Three things are kept in step on
 * every transition — React state (for components), the module token in
 * `api/client.ts` (for outgoing requests) and the snapshot in `auth-store.ts`
 * (for the router's `beforeLoad`) — which is why they are all written through
 * the single `apply()` below.
 */
export function AuthProvider({ children, initialUser, initialToken }: AuthProviderProps) {
  const seeded = Boolean(initialUser && initialToken);

  const [session, setSession] = useState<Session>(() => {
    const initial: Session = seeded
      ? { status: 'authenticated', user: initialUser ?? null, token: initialToken ?? null }
      : { status: 'loading', user: null, token: null };

    // Written during the initializer, not an effect: the router renders below
    // this provider and its `beforeLoad` runs before any effect would have.
    setAuthSnapshot({ status: initial.status, user: initial.user });
    setAuthToken(initial.token);
    return initial;
  });

  const apply = useCallback((next: Session) => {
    setAuthToken(next.token);
    setAuthSnapshot({ status: next.status, user: next.user });
    setSession(next);
  }, []);

  const logout = useCallback(() => {
    clearStoredToken();
    apply(SIGNED_OUT);
  }, [apply]);

  // `logout` is stable, but the 401 handler is registered once and must not be
  // torn down and re-registered on every render.
  const logoutRef = useRef(logout);
  logoutRef.current = logout;

  useEffect(() => {
    setUnauthorizedHandler(() => logoutRef.current());
    return () => setUnauthorizedHandler(null);
  }, []);

  // Restore a stored token, then prove it is still good. An expired or revoked
  // token looks identical to a valid one from here, so only the server can say.
  useEffect(() => {
    if (seeded) return;

    const stored = readStoredToken();
    if (!stored) {
      apply(SIGNED_OUT);
      return;
    }

    let cancelled = false;
    setAuthToken(stored);

    authApi
      .me()
      .then((user) => {
        if (!cancelled) apply({ status: 'authenticated', user, token: stored });
      })
      .catch(() => {
        if (!cancelled) {
          clearStoredToken();
          apply(SIGNED_OUT);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [apply, seeded]);

  const adopt = useCallback(
    (response: AuthResponse) => {
      writeStoredToken(response.token);
      apply({ status: 'authenticated', user: response.user, token: response.token });
      return response.user;
    },
    [apply],
  );

  const login = useCallback(
    (payload: LoginPayload) => authApi.login(payload).then(adopt),
    [adopt],
  );

  const register = useCallback(
    (payload: RegisterPayload) => authApi.register(payload).then(adopt),
    [adopt],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      status: session.status,
      user: session.user,
      token: session.token,
      isAuthenticated: session.status === 'authenticated',
      login,
      register,
      logout,
    }),
    [session, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
