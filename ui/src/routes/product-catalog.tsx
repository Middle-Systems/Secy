import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { rootRoute } from '@/routes/__root';

export const productCatalogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/product-catalog',
  component: lazyRouteComponent(
    () => import('@/components/product-catalog/ProductCatalogView'),
    'ProductCatalogView',
  ),
});
