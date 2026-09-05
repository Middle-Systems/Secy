import { createRoute } from '@tanstack/react-router';
import { Flame } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { rootRoute } from '@/routes/__root';

function KevDatabasePage() {
  return (
    <PlaceholderPage
      title="KEV Database"
      description="The CISA Known Exploited Vulnerabilities catalog."
      icon={Flame}
    />
  );
}

export const kevDatabaseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/kev-database',
  component: KevDatabasePage,
});
