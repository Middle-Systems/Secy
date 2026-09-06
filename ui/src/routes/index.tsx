import { createRoute, redirect } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

/** `/` has no view of its own — send it to the dashboard. */
export const indexRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/dashboard' });
  },
});
