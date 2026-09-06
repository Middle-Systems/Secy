import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const epssDatabaseRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/epss-database',
  component: lazyRouteComponent(
    () => import('@/components/epss-database/EpssDatabaseView'),
    'EpssDatabaseView',
  ),
});
