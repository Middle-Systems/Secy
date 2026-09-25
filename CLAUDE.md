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
  `/osv`, `/osv/ingest`, `/cve-list/ingest`, `/products`, `POST /sbom` (tag-driven upload — M1a;
  resolves its product from repeated `tag=key=value` params via the tenant's configured product
  tag key, default `secy:product`; untagged/unresolved lands in the "Unassigned" bucket) and
  `POST /sbom/{productId}/sboms` (manual upload) both take an optional `?stage=` param
  (`SOURCE`/`BUILD`/`ANALYZED`/`DEPLOYED`, case-insensitive, 400 on anything else — M1e; wins over
  any stage the document itself declares, e.g. CycloneDX `metadata.lifecycles`),
  `/sbom/{id}/vulnerabilities`, `/settings/product-tagging` (GET/PUT the tenant's product tag key
  — M1a), `/products/{id}/owners` (GET/POST, `DELETE /{ownerId}` — manual ownership links, M1b),
  `/actionable`, `/actionable/{id}`, `/compromise`, `/compromise/{id}`, `/lifecycle-drift`,
  `/lifecycle-drift/{id}` (M1e — Source/Build/Analyzed/Deployed SBOM diff findings; not part of
  `/actionable`), `/stats/dashboard`,
  `/assets`, `/assets/scan/{trivy,grype}`, `/compliance/reports` (+ `/{id}`, `/{id}/scan`,
  `/{id}/misconfigurations`), `/connectors` (+ `/{id}`, `/{id}/sync` — Phase 6b agentless source
  connectors, GitHub only for now), `POST /lineage/rebuild` (M1d — queues a full rebuild of the
  Apache AGE lineage graph from Postgres; 503 when `secy.lineage.enabled=false` or no graph writer
  is configured, which is the default everywhere until you opt in — see below).
- Paged responses are Spring `Page` shape: `content`, `totalElements`, `totalPages`, 0-indexed.
- Every endpoint except `/auth/**`, `/actuator/health` and the OpenAPI docs requires
  `Authorization: Bearer <jwt>`. Get one from `POST /auth/login`; the first account created via
  `POST /auth/register` becomes `ADMIN`.

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

The devcontainer image is Node 20 + JDK 17, no Docker. The backend never starts a database
itself (`spring.docker.compose.enabled=false`). Run PostgreSQL on the host
(`docker compose -f api/compose.yaml up -d --build`, persistent volume) and `./gradlew bootRun` in
the devcontainer reaches it via `host.docker.internal:5433` — `SECY_DB_URL` is preset to that in
`.devcontainer/devcontainer.json`. Tests never need a DB (H2, `src/test/resources`).

`api/compose.yaml`'s Postgres image now needs `--build` the first time after pulling M1d (it
layers the Apache AGE extension onto `postgres:16` — see `api/docker/postgres-age/Dockerfile`);
your existing `secy-pgdata` volume is preserved. The lineage graph itself stays off regardless
until `SECY_LINEAGE_ENABLED=true` is also set.

## Conventions

- UI: see `ui/README.md` for the full frontend guide. In short — server state goes through the
  hooks in `src/api/queries.ts` (never call `fetch` from a component), routes are code-based
  under `src/routes/` and assembled in `src/routeTree.ts`, shared types live in `src/api/types.ts`,
  and `@/` aliases `ui/src/`. Style with Tailwind + the shadcn primitives in `src/components/ui/`.
- API: `net.jdesive.secy` package; `controller` / `service` / `persistence` (repo + `entity`) / `model`.
- API config is env-var driven: `NVD_API_KEY`, `SECY_DB_URL`, `SECY_DB_USERNAME`, `SECY_DB_PASSWORD`,
  `SECY_AUTH_JWT_SECRET` (HS256 signing key, ≥32 chars; blank generates a throwaway one per process
  and logs a WARN), `SECY_AUTH_REGISTRATION_ENABLED`,
  `SECY_ACTIONABLE_EPSS_THRESHOLD` (default `0.1` — an alert is actionable when its CVE is
  KEV-listed **or** its EPSS score is strictly above this),
  `SECY_OSV_ECOSYSTEMS` (comma-separated OSV ecosystem names mirrored by `POST /osv/ingest`;
  default `npm,Maven,PyPI,Go,NuGet,RubyGems,crates.io,Packagist,Hex,Pub`),
  `SECY_GITHUB_TOKEN` (a GitHub PAT with `repo` + `read:org` scope, one token instance-wide, used
  by every `SourceConnector` — blank means a connector sync 401/403s per-repo, skipped not fatal),
  `SECY_LINEAGE_ENABLED` (M1d — default `false`; the Apache AGE lineage graph writer only exists as
  a bean when this is `true`, so a Postgres without the AGE extension installed is unaffected),
  `SECY_LINEAGE_AGE_LIBRARY` (default `age` — the shared library `LOAD`ed before every graph write),
  `SECY_LINEAGE_BATCH_SIZE` (default `500` — rows per Cypher `UNWIND` batch on a rebuild)
  (see `application.properties` for defaults). For local dev, copy
  `application-local.properties.example` → `application-local.properties` (git-ignored) and fill in
  the NVD key. Never put a real secret in a tracked file.
