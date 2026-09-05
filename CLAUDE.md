# Secy — monorepo guide

Security posture management platform. Ingests vulnerability feeds (NVD, FIRST EPSS, CISA KEV),
correlates them against assets (SBOMs / infra), and surfaces the small set of **actionable**
items: KEV-listed OR EPSS > 0.1.

## Layout

| Path   | Stack | Run from | Notes |
|--------|-------|----------|-------|
| `ui/`  | Vite 6, React 18, TypeScript, TanStack Router + Query + Table, Tailwind + shadcn/ui, Recharts, lucide-react, sonner | `ui/` | `npm run dev` → Vite on 0.0.0.0:4200 |
| `api/` | Spring Boot 3.3.4, Java 17, Gradle (wrapper), Spring Data JPA + REST, Lombok | `api/` | `./gradlew bootRun` on :8080; H2 for tests, PostgreSQL otherwise |

`api/` was merged from the former `secy-api` repo via `git subtree` (prefix `api/`), history preserved.

## How the two connect

- UI calls `/api/**`; `ui/vite.config.ts` (`server.proxy`) rewrites `^/api` → backend root and targets:
  - `API_TARGET` env if set, else
  - `host.docker.internal:8080` when `DEVCONTAINER=true` (frontend in container, backend on host), else
  - `localhost:8080`.
- Backend endpoints: `/nvd/search`, `/nvd/ingest`, `/kev`, `/kev/ingest`, `/epss`, `/epss/ingest`,
  `/products`, `/sbom/{id}/vulnerabilities`, `/stats/dashboard`, plus CIS/docker controllers.
- Paged responses are Spring `Page` shape: `content`, `totalElements`, `totalPages`, 0-indexed.

## Commands

```bash
# UI
cd ui && npm install
npm run dev          # dev server on 0.0.0.0:4200 (alias: npm start)
npm run build        # tsc --noEmit + vite build → dist/
npm test             # vitest (run once); npm run test:watch to watch
npm run typecheck    # tsc --noEmit
npm run lint         # eslint; npm run format for prettier

# API
cd api && ./gradlew bootRun
./gradlew build      # compile + test
./gradlew test
```

The devcontainer image is Node 20 + JDK 17. Docker is NOT available inside it, so
`spring-boot-docker-compose` (auto-Postgres) won't work in-container — run the DB on the host,
or run the backend on the host entirely.

## Conventions

- UI: see `ui/README.md` for the full frontend guide. In short — server state goes through the
  hooks in `src/api/queries.ts` (never call `fetch` from a component), routes are code-based
  under `src/routes/` and assembled in `src/routeTree.ts`, shared types live in `src/api/types.ts`,
  and `@/` aliases `ui/src/`. Style with Tailwind + the shadcn primitives in `src/components/ui/`.
- API: `net.jdesive.secy` package; `controller` / `service` / `persistence` (repo + `entity`) / `model`.
- API config is env-var driven: `NVD_API_KEY`, `SECY_DB_URL`, `SECY_DB_USERNAME`, `SECY_DB_PASSWORD`
  (see `application.properties` for defaults). For local dev, copy
  `application-local.properties.example` → `application-local.properties` (git-ignored) and fill in
  the NVD key. Never put a real secret in a tracked file.
