import { createRootRoute } from '@tanstack/react-router';

import { AppShell } from '@/components/layout/AppShell';
import { NotFound } from '@/routes/not-found';

/**
 * Root route. Renders the app shell (header / sidenav / footer) around every
 * child route's `<Outlet />`.
 *
 * This file must not import any child route, or the route tree will cycle —
 * children import `rootRoute` from here and `routeTree.tsx` assembles them.
 */
export const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFound,
});
