import type { ReactNode } from 'react';
import { QueryClientProvider } from '@tanstack/react-query';
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
  type AnyRoute,
  type AnyRouter,
} from '@tanstack/react-router';
import { render, type RenderOptions } from '@testing-library/react';

import { AuthProvider } from '@/auth/AuthProvider';
import type { AuthUser } from '@/auth/types';
import { RoutePending } from '@/components/common/RoutePending';
import { createQueryClient } from '@/lib/query-client';
import { routeTree } from '@/routeTree';

/**
 * A pre-authenticated account for tests.
 *
 * `displayName` is `jdesive` because that is the name the shell smoke test
 * asserts on — it used to be hard-coded in `Header`, and is now whatever the
 * session says.
 */
export const TEST_USER: AuthUser = {
  id: '00000000-0000-4000-8000-000000000001',
  email: 'jdesive@secy.test',
  displayName: 'jdesive',
  role: 'ADMIN',
  enabled: true,
  createdAt: '2024-01-01T00:00:00',
};

export const TEST_TOKEN = 'test.jwt.token';

/**
 * Seeding both `initialUser` and `initialToken` puts `AuthProvider` straight
 * into the authenticated state, so no test hits `/auth/me` — and every route
 * behind the guard renders as it would for a signed-in user.
 */
function withProviders(children: ReactNode, queryClient = createQueryClient()) {
  return (
    <AuthProvider initialUser={TEST_USER} initialToken={TEST_TOKEN}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </AuthProvider>
  );
}

/**
 * Render a plain component with the app's providers (no router).
 * Use this for anything that does not contain a `<Link>` or read route state.
 */
export function renderWithProviders(ui: ReactNode, options?: RenderOptions) {
  const queryClient = createQueryClient();
  return render(withProviders(ui, queryClient), options);
}

/**
 * Mount the whole app (shell + routes) at a given URL, using an in-memory
 * history so tests can navigate without a browser.
 *
 * Pass `authenticated: false` to exercise the signed-out path — the guard in
 * `routes/_app.tsx` then redirects to `/login`.
 */
export function renderApp(initialPath = '/dashboard', options: { authenticated?: boolean } = {}) {
  const { authenticated = true } = options;

  const queryClient = createQueryClient();
  const router = createRouter({
    routeTree: routeTree as AnyRoute,
    history: createMemoryHistory({ initialEntries: [initialPath] }),
    // Route views are code-split via `lazyRouteComponent` (see `src/routes/*`);
    // mirror the real router so tests render the same pending fallback, and show
    // it immediately so the shell commits without waiting out `defaultPendingMs`.
    defaultPendingComponent: RoutePending,
    defaultPendingMs: 0,
  });

  const tree = (
    <AuthProvider
      initialUser={authenticated ? TEST_USER : null}
      initialToken={authenticated ? TEST_TOKEN : null}
    >
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router as AnyRouter} />
      </QueryClientProvider>
    </AuthProvider>
  );

  const result = render(tree);

  return { ...result, router, queryClient };
}
