import { createRoute } from '@tanstack/react-router';

import { DashboardView } from '@/components/dashboard/DashboardView';
import { rootRoute } from '@/routes/__root';

export const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  component: DashboardView,
});
