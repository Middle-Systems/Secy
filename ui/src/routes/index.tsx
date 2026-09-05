import { createRoute, redirect } from '@tanstack/react-router';

import { rootRoute } from '@/routes/__root';

/** `/` has no view of its own — send it to the dashboard. */
export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/dashboard' });
  },
});
