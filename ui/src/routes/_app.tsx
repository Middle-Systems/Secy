import type { ReactNode } from 'react';
import { Navigate, createRoute, redirect, useRouterState } from '@tanstack/react-router';

import { getAuthSnapshot } from '@/auth/auth-store';
import { useAuth } from '@/auth/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { RoutePending } from '@/components/common/RoutePending';
import { rootRoute } from '@/routes/__root';
import { NotFound } from '@/routes/not-found';

/**
 * The shell, gated on a session.
 *
 * There are two guards on purpose, covering different moments:
 *
 * - `beforeLoad` catches a navigation (including a cold load of a deep link)
 *   and redirects before anything renders, so the shell never flashes.
 * - this component catches the session *ending* underneath a page that is
 *   already mounted — a sign-out, or a 401 from an expired token — which no
 *   `beforeLoad` will ever re-run for.
 *
 * Both read the same state, so they cannot disagree.
 */
function GuardedShell({ children }: { children?: ReactNode }) {
  const { status } = useAuth();
  const href = useRouterState({ select: (state) => state.location.href });

  if (status === 'loading') {
    return <RoutePending />;
  }

  if (status !== 'authenticated') {
    return <Navigate to="/login" search={{ redirect: href }} replace />;
  }

  return <AppShell>{children}</AppShell>;
}

/** Renders the matched child route inside the shell. */
function AuthenticatedShell() {
  return <GuardedShell />;
}

/**
 * Same chrome, spinner instead of the outlet.
 *
 * The shell used to live on the root route, which the router always renders.
 * An ordinary match is replaced by its pending fallback while the branch loads,
 * so without this the header and sidenav would vanish for the duration of a
 * slow lazy route chunk.
 */
function PendingShell() {
  return (
    <GuardedShell>
      <RoutePending />
    </GuardedShell>
  );
}

/**
 * Pathless layout route: contributes no path segment, so `/dashboard` stays
 * `/dashboard` while gaining the shell and the guard. Every route except
 * `/login` hangs off this.
 */
export const appLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: '_app',
  beforeLoad: ({ location }) => {
    // Read through the store rather than router context: the guard has to see
    // the state as of *this* navigation, and context lags by one update.
    if (getAuthSnapshot().status === 'unauthenticated') {
      throw redirect({ to: '/login', search: { redirect: location.href }, replace: true });
    }
  },
  component: AuthenticatedShell,
  pendingComponent: PendingShell,
  // Unknown paths under the shell keep the shell, instead of dropping to a bare
  // 404 page from the root route.
  notFoundComponent: NotFound,
});
