import { createRouter } from '@tanstack/react-router';

import { RoutePending } from '@/components/common/RoutePending';
import { routeTree } from '@/routeTree';

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
  // TanStack Query owns caching; the router should not also stale-check loaders.
  defaultPreloadStaleTime: 0,
  // Shown while a lazily code-split route view chunk is loading.
  defaultPendingComponent: RoutePending,
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
