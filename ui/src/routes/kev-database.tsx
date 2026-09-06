import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const kevDatabaseRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/kev-database',
  component: lazyRouteComponent(
    () => import('@/components/kev-database/KevDatabaseView'),
    'KevDatabaseView',
  ),
});
