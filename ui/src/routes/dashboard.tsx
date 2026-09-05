import { createRoute } from '@tanstack/react-router';
import { ChartLine } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { rootRoute } from '@/routes/__root';

function DashboardPage() {
  return (
    <PlaceholderPage
      title="Dashboard"
      description="Threat intelligence and security posture at a glance."
      icon={ChartLine}
    />
  );
}

export const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  component: DashboardPage,
});
