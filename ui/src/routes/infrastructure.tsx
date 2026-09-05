import { createRoute } from '@tanstack/react-router';
import { Server } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { rootRoute } from '@/routes/__root';

function InfrastructurePage() {
  return (
    <PlaceholderPage
      title="Infrastructure"
      description="Hosts and services correlated against the vulnerability feeds."
      icon={Server}
    />
  );
}

export const infrastructureRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/infrastructure',
  component: InfrastructurePage,
});
