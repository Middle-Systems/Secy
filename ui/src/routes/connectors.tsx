import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const connectorsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/connectors',
  component: lazyRouteComponent(
    () => import('@/components/connectors/ConnectorsView'),
    'ConnectorsView',
  ),
});
