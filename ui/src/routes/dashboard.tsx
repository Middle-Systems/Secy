import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const dashboardRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/dashboard',
  component: lazyRouteComponent(
    () => import('@/components/dashboard/DashboardView'),
    'DashboardView',
  ),
});
