# Secy — monorepo guide

Security posture management platform. Ingests vulnerability feeds (NVD, FIRST EPSS, CISA KEV),
correlates them against assets (SBOMs / infra), and surfaces the small set of **actionable**
items: KEV-listed OR EPSS > 0.1.

## Layout

| Path   | Stack | Run from | Notes |
|--------|-------|----------|-------|
| `ui/`  | Angular 18, module-based (NOT standalone), MDB Angular UI Kit 7, ng2-charts/chart.js, ngx-toastr | `ui/` | `npm start` → `ng serve --host 0.0.0.0` on :4200 |
| `api/` | Spring Boot 3.3.4, Java 17, Gradle (wrapper), Spring Data JPA + REST, Lombok | `api/` | `./gradlew bootRun` on :8080; H2 for tests, PostgreSQL otherwise |

`api/` was merged from the former `secy-api` repo via `git subtree` (prefix `api/`), history preserved.

## How the two connect

- UI calls `/api/**`; `ui/src/proxy.conf.js` rewrites `^/api` → backend root and targets:
  - `API_TARGET` env if set, else
  - `host.docker.internal:8080` when `DEVCONTAINER=true` (frontend in container, backend on host), else
  - `localhost:8080`.
- Backend endpoints: `/nvd/search`, `/nvd/ingest`, `/kev`, `/kev/ingest`, `/epss`, `/epss/ingest`,
  `/products`, `/sbom/{id}/vulnerabilities`, `/stats/dashboard`, plus CIS/docker controllers.
- Paged responses are Spring `Page` shape: `content`, `totalElements`, `totalPages`, 0-indexed.

## Commands

```bash
# UI
cd ui && npm ci
npm start            # dev server :4200
npm run build        # prod build
npm test             # karma/jasmine (only default specs exist)

# API
cd api && ./gradlew bootRun
./gradlew build      # compile + test
./gradlew test
```

The devcontainer image is Node 20 + JDK 17. Docker is NOT available inside it, so
`spring-boot-docker-compose` (auto-Postgres) won't work in-container — run the DB on the host,
or run the backend on the host entirely.

## Conventions

- UI: components are declared in NgModules (`ui/src/app/views/views.module.ts`,
  `layout.module.ts`), `standalone: false`. Match existing MDB + Bootstrap-utility class style.
- API: `net.jdesive.secy` package; `controller` / `service` / `persistence` (repo + `entity`) / `model`.
- `api/src/main/resources/application.properties` currently holds real-looking DB creds and an
  NVD API key — treat as secrets to externalize, don't copy into new files.
