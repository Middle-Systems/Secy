import { createRoute } from '@tanstack/react-router';

import { ProductCatalogView } from '@/components/product-catalog/ProductCatalogView';
import { rootRoute } from '@/routes/__root';

export const productCatalogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/product-catalog',
  component: ProductCatalogView,
});
