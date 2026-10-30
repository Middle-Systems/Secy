import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

/** M1k — the leadership view's read-only posture aggregates screen. */
export const leadershipRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/leadership',
  component: lazyRouteComponent(
    () => import('@/components/leadership/LeadershipView'),
    'LeadershipView',
  ),
});
