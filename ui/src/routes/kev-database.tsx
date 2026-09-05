import { createRoute } from '@tanstack/react-router';

import { KevDatabaseView } from '@/components/kev-database/KevDatabaseView';
import { rootRoute } from '@/routes/__root';

export const kevDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/kev-database',
  component: KevDatabaseView,
});
