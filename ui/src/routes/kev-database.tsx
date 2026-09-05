import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { rootRoute } from '@/routes/__root';

export const kevDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/kev-database',
  component: lazyRouteComponent(
    () => import('@/components/kev-database/KevDatabaseView'),
    'KevDatabaseView',
  ),
});
