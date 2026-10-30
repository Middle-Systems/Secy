import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

/** M1k — the software-engineer view's "My Action Items" home screen. */
export const myWorkRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/my-work',
  component: lazyRouteComponent(() => import('@/components/my-work/MyWorkView'), 'MyWorkView'),
});
