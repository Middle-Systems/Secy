import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const infrastructureRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/infrastructure',
  component: lazyRouteComponent(
    () => import('@/components/infrastructure/InfrastructureView'),
    'InfrastructureView',
  ),
});
