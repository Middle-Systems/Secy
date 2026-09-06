import { rootRoute } from '@/routes/__root';
import { appLayoutRoute } from '@/routes/_app';
import { complianceRoute } from '@/routes/compliance';
import { cveDatabaseRoute } from '@/routes/cve-database';
import { dashboardRoute } from '@/routes/dashboard';
import { epssDatabaseRoute } from '@/routes/epss-database';
import { indexRoute } from '@/routes/index';
import { infrastructureRoute } from '@/routes/infrastructure';
import { kevDatabaseRoute } from '@/routes/kev-database';
import { loginRoute } from '@/routes/login';
import { productCatalogRoute } from '@/routes/product-catalog';

/**
 * Code-based TanStack Router route tree (no file-based generation).
 *
 * Two branches hang off the root:
 *
 *   root
 *   ├── /login          bare screen — no shell, no session required
 *   └── _app            pathless layout: renders the AppShell behind the auth
 *       ├── /               guard, and contributes no path segment of its own
 *       ├── /dashboard
 *       └── …
 *
 * To add a route:
 *   1. create `src/routes/<name>.tsx` exporting a `createRoute({ getParentRoute: () => appLayoutRoute, path, component })`
 *   2. import it here and add it to the `appLayoutRoute.addChildren` array below
 *   3. add a nav entry in `src/components/layout/Sidenav.tsx` if it needs one
 *
 * Anything parented to `rootRoute` instead of `appLayoutRoute` renders without
 * the shell *and without the auth guard* — `/login` is the only route that
 * should.
 *
 * Route paths are string-literal typed off this tree, so `<Link to="...">`
 * fails to compile for a path that does not exist.
 */
export const routeTree = rootRoute.addChildren([
  loginRoute,
  appLayoutRoute.addChildren([
    indexRoute,
    dashboardRoute,
    cveDatabaseRoute,
    kevDatabaseRoute,
    epssDatabaseRoute,
    productCatalogRoute,
    infrastructureRoute,
    complianceRoute,
  ]),
]);
