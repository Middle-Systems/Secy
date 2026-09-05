import { createRoute } from '@tanstack/react-router';

import { EpssDatabaseView } from '@/components/epss-database/EpssDatabaseView';
import { rootRoute } from '@/routes/__root';

export const epssDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/epss-database',
  component: EpssDatabaseView,
});
