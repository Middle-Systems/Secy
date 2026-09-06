import { createRoute, lazyRouteComponent } from '@tanstack/react-router';

import { appLayoutRoute } from '@/routes/_app';

export const productCatalogRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: '/product-catalog',
  component: lazyRouteComponent(
    () => import('@/components/product-catalog/ProductCatalogView'),
    'ProductCatalogView',
  ),
});
