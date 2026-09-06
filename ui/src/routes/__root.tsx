import { Outlet, createRootRoute } from '@tanstack/react-router';

import { NotFound } from '@/routes/not-found';

/**
 * Root route. Renders nothing of its own — just the matched child.
 *
 * The app shell moved down to the pathless `_app` layout route
 * (`src/routes/_app.tsx`), because `/login` has to render *outside* the shell
 * while every other route renders inside it and behind the auth guard.
 *
 * This file must not import any child route, or the route tree will cycle —
 * children import `rootRoute` from here and `routeTree.ts` assembles them.
 */
export const rootRoute = createRootRoute({
  component: Outlet,
  notFoundComponent: NotFound,
});
