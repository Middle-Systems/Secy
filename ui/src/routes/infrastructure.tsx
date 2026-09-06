import { createRoute } from '@tanstack/react-router';
import { Server } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { appLayoutRoute } from '@/routes/_app';

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
  getParentRoute: () => appLayoutRoute,
  path: '/infrastructure',
  component: InfrastructurePage,
});
