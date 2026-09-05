import { createRoute } from '@tanstack/react-router';
import { Boxes } from 'lucide-react';

import { PlaceholderPage } from '@/components/common/PlaceholderPage';
import { rootRoute } from '@/routes/__root';

function ProductCatalogPage() {
  return (
    <PlaceholderPage
      title="Product Catalog"
      description="Products, their SBOMs, and the alerts raised against them."
      icon={Boxes}
    />
  );
}

export const productCatalogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/product-catalog',
  component: ProductCatalogPage,
});
