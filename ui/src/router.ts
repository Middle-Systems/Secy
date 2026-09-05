import { createRouter } from '@tanstack/react-router';

import { routeTree } from '@/routeTree';

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
  // TanStack Query owns caching; the router should not also stale-check loaders.
  defaultPreloadStaleTime: 0,
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
