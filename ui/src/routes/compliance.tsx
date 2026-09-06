import { createRoute } from '@tanstack/react-router';
import { ClipboardCheck } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { appLayoutRoute } from '@/routes/_app';

function CompliancePage() {
  return (
    <PlaceholderPage
      title="Compliance"
      description="Benchmark results and control coverage."
      icon={ClipboardCheck}
    />
  );
}

export const complianceRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/compliance',
  component: CompliancePage,
});
