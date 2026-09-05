# Secy UI

React frontend for the Secy security-posture platform. Talks to the Spring Boot
API in `../api` through a dev-server proxy on `/api`.

## Commands

Run everything from `ui/`.

```bash
npm install          # install dependencies

npm run dev          # dev server on 0.0.0.0:4200 (alias: npm start)
npm run build        # tsc --noEmit + vite build -> dist/
npm run preview      # serve the production build

npm test             # vitest, single run
npm run test:watch   # vitest in watch mode
npm run typecheck    # tsc --noEmit
npm run lint         # eslint (npm run lint:fix to autofix)
npm run format       # prettier --write
```

The backend must be running for any data to appear:

```bash
cd ../api && ./gradlew bootRun     # :8080
```

### Backend target

`vite.config.ts` proxies `/api/**` to the backend and strips the `/api` prefix
(`/api/kev` -> `GET /kev`). The target is chosen in this order:

1. `API_TARGET` if set — `API_TARGET=http://localhost:8080 npm run dev`
2. `http://host.docker.internal:8080` when `DEVCONTAINER` is set (UI in the
   devcontainer, backend on the host)
3. `http://localhost:8080`

## Stack

Vite 6 · React 18 · TypeScript · TanStack Router (code-based) · TanStack Query ·
TanStack Table · Tailwind + shadcn/ui (Radix) · Recharts · react-hook-form + zod ·
sonner · lucide-react · Vitest + React Testing Library.

## Layout

```
src/
  main.tsx              app entry: QueryClientProvider + RouterProvider
  router.ts             createRouter + the Register type declaration
  routeTree.ts          assembles the route tree (add new routes here)
  routes/               one file per route
    __root.tsx          root route: renders AppShell, owns the 404
    index.tsx           '/' -> redirects to /dashboard
    dashboard.tsx …     one placeholder per view
    not-found.tsx       the 404 component
  components/
    ui/                 shadcn primitives (generated; edit in place)
    layout/             AppShell, Header, Sidenav, Footer
    common/             shared app components (PlaceholderPage lives here)
  api/
    client.ts           typed fetch wrapper, base '/api', ApiError
    types.ts            shared API types
    queries.ts          TanStack Query hooks + the queryKeys factory
  lib/
    utils.ts            cn() — shadcn class helper
    query-client.ts     QueryClient defaults
  styles/index.css      Tailwind layers, design tokens, shell geometry
  test/                 setup, render helpers, smoke test
```

`@/` aliases `src/` (configured in both `vite.config.ts` and `tsconfig.json`).

## Conventions

**Server state goes through `src/api/queries.ts`.** Never call `fetch` or `api`
directly from a component. If an endpoint has no hook yet, add one there so
caching, invalidation and query keys stay in one place. Query keys always come
from the `queryKeys` factory — never inline a key array.

**The shell owns the scrolling.** `html, body { overflow: hidden }`; the only
scroll container is `.app-content` in `AppShell`. A view must never add its own
full-page scroller. Views render inside a padded container, so start with your
page heading — no outer wrapper needed.

**Shell dimensions are Tailwind spacing keys**, not magic numbers: `w-sidenav`
(240px), `h-header` (58px), `h-footer` (45px).

**Colors come from the design tokens** in `styles/index.css` — `bg-card`,
`text-muted-foreground`, `border-border`, `bg-primary`, `text-destructive`, and
the severity ramp `text-severity-{critical,high,medium,low}`. Don't hard-code
hex values.

**Toasts** are fired from the view with `import { toast } from 'sonner'`. The
mutation hooks deliberately don't raise them, so the copy stays local to the
screen that triggered the action.

### Adding a route

1. Create `src/routes/<name>.tsx`:

   ```tsx
   import { createRoute } from '@tanstack/react-router';
   import { rootRoute } from '@/routes/__root';

   function MyPage() {
     return <div>…</div>;
   }

   export const myRoute = createRoute({
     getParentRoute: () => rootRoute,
     path: '/my-path',
     component: MyPage,
   });
   ```

2. Import it in `src/routeTree.ts` and add it to `rootRoute.addChildren([...])`.
3. Add a nav entry in `src/components/layout/Sidenav.tsx` if it needs one.

Route files must import `rootRoute` from `__root` — never the other way around,
or the tree cycles. Paths are literal-typed off the tree, so `<Link to="...">`
won't compile for a route that doesn't exist.

### Adding a shadcn component

```bash
npx shadcn@latest add <component>
```

Already installed: `button`, `card`, `input`, `badge`, `separator`,
`dropdown-menu`, `dialog`, `table`, `skeleton`, `label`, `select`, `tooltip`,
`sonner`.

Commonly needed next and **not** yet installed: `form`, `checkbox`, `tabs`,
`popover`, `command`, `alert`, `alert-dialog`, `sheet`, `switch`, `textarea`,
`pagination`, `progress`, `scroll-area`.

Note: the `sonner` block has been edited to drop its `next-themes` dependency —
don't regenerate it without reapplying that.

## API reference

Types in `src/api/types.ts`: `Page<T>`, `Pageable`, `Sort`, `PageParams`,
`DashboardStats`, `KEV`, `EPSS`, `Vulnerability`, `BaseSeverity`, `Product`,
`SBOM`, `SbomStatus`, `SBOMComponent`, `SBOMTool`, `VulnerabilityAlert`,
`CreateProductPayload`.

Hooks in `src/api/queries.ts`:

| Hook | Request |
|------|---------|
| `useDashboardStats()` | `GET /api/stats/dashboard` |
| `useKevPage({ page, size, search })` | `GET /api/kev` |
| `useEpssPage({ page, size, search })` | `GET /api/epss` |
| `useNvdSearch({ search, page, size })` | `GET /api/nvd/search` |
| `useProducts()` | `GET /api/products` |
| `useSbomVulnerabilities(sbomId)` | `GET /api/sbom/:id/vulnerabilities` |
| `useIngestKev()` | `GET /api/kev/ingest` |
| `useIngestEpss()` | `GET /api/epss/ingest` |
| `useIngestNvd()` | `GET /api/nvd/ingest` |
| `useCreateProduct()` | `POST /api/products` |
| `useDeleteProduct()` | `DELETE /api/products/:id` |
| `useUploadSbom()` | `POST /api/sbom/:productId/sboms` |

Paged hooks default to `page: 0`, `size: 15`, `search: ''` and keep the previous
page rendered while the next loads. Every hook accepts a second argument of
TanStack Query options to override defaults.

Two shape gotchas, both confirmed against a live backend:

- **Dates are strings**, not `Date` objects, everywhere. Parse at the point of
  display.
- **`GET /api/products` does not return the roll-up counters.** Only `id`,
  `name`, `description`, `createdAt` and `sboms` come back today, so
  `actionableCount`, `vulnerabilityCount`, `lastScanned`, `activeSbomId` and
  `activeSbomStatus` are optional — guard them (`product.actionableCount ?? 0`).

## Testing

`src/test/render.tsx` provides `renderWithProviders(ui)` for a plain component
and `renderApp(path)` to mount the whole shell on an in-memory history.
