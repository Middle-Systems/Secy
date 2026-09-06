import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

/** `/` is the Actionable Items view — the funnel output is the first screen. */
export const indexRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/',
  component: lazyRouteComponent(
    () => import('@/components/actionable/ActionableView'),
    'ActionableView',
  ),
});
