import { rootRoute } from '@/routes/__root';
import { complianceRoute } from '@/routes/compliance';
import { cveDatabaseRoute } from '@/routes/cve-database';
import { dashboardRoute } from '@/routes/dashboard';
import { epssDatabaseRoute } from '@/routes/epss-database';
import { indexRoute } from '@/routes/index';
import { infrastructureRoute } from '@/routes/infrastructure';
import { kevDatabaseRoute } from '@/routes/kev-database';
import { productCatalogRoute } from '@/routes/product-catalog';

/**
 * Code-based TanStack Router route tree (no file-based generation).
 *
 * To add a route:
 *   1. create `src/routes/<name>.tsx` exporting a `createRoute({ getParentRoute: () => rootRoute, path, component })`
 *   2. import it here and add it to the array below
 *   3. add a nav entry in `src/components/layout/Sidenav.tsx` if it needs one
 *
 * Route paths are string-literal typed off this tree, so `<Link to="...">`
 * fails to compile for a path that does not exist.
 */
export const routeTree = rootRoute.addChildren([
  indexRoute,
  dashboardRoute,
  cveDatabaseRoute,
  kevDatabaseRoute,
  epssDatabaseRoute,
  productCatalogRoute,
  infrastructureRoute,
  complianceRoute,
]);
