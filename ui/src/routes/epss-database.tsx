import { createRoute } from '@tanstack/react-router';
import { Percent } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { rootRoute } from '@/routes/__root';

function EpssDatabasePage() {
  return (
    <PlaceholderPage
      title="EPSS Database"
      description="FIRST exploit-prediction scores for every CVE."
      icon={Percent}
    />
  );
}

export const epssDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/epss-database',
  component: EpssDatabasePage,
});
