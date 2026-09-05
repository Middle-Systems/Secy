import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { rootRoute } from '@/routes/__root';

export const epssDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/epss-database',
  component: lazyRouteComponent(
    () => import('@/components/epss-database/EpssDatabaseView'),
    'EpssDatabaseView',
  ),
});
