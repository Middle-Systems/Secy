import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const complianceRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/compliance',
  component: lazyRouteComponent(
    () => import('@/components/compliance/ComplianceView'),
    'ComplianceView',
  ),
});
