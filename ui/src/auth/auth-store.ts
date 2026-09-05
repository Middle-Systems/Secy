import type { AuthSnapshot } from '@/auth/types';

/**
 * A synchronous mirror of the provider's auth state, for readers that are not
 * React components.
 *
 * The route guard lives in `beforeLoad` (`src/routes/_app.tsx`), which the
 * router may call outside of a render — it cannot use `useAuth()`, and threading
 * the value through router context would let it go stale for exactly one
 * navigation after a sign-in or sign-out, which is the navigation that matters.
 * `AuthProvider` writes here in the same tick it updates React state, so both
 * readers always agree.
 */
let snapshot: AuthSnapshot = { status: 'loading', user: null };

export function getAuthSnapshot(): AuthSnapshot {
  return snapshot;
}

export function setAuthSnapshot(next: AuthSnapshot): void {
  snapshot = next;
}
