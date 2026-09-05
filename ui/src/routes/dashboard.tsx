import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { rootRoute } from '@/routes/__root';

export const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  component: lazyRouteComponent(
    () => import('@/components/dashboard/DashboardView'),
    'DashboardView',
  ),
});
