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
  is configured, which is the default everywhere until you opt in — see below), `POST /vex`
  (M1f — `?origin=TENANT|VENDOR` required, `?productId=` optional; validates an OpenVEX/CSAF
  2.0-subset/CycloneDX VEX document synchronously, then queues a `VEX_UPLOAD` job), `/vex/documents`
  (+ `/{id}`, `/{id}/statements`, `POST /{id}/deactivate`), `/vex/statements`,
  `POST /vex/reconcile`, `/vex/settings/precedence` (GET/PUT the tenant's precedence policy),
  `/cbom/assets` (+ `/{id}`), `/cbom/quantum-findings` (+ `/{id}`) (M1g — CycloneDX 1.6
  `cryptographic-asset` inventory and Shor-vulnerability findings; not part of `/actionable`). CBOM
  data is not a separate upload — it rides on `POST /sbom`/`POST /sbom/{productId}/sboms` as ordinary
  components of type `cryptographic-asset` inside a normal CycloneDX document, extracted only when
  `specVersion >= 1.6`. A *standalone* CBOM (every component crypto-typed) uses the same endpoints
  but replaces the product's/stage's whole active SBOM like any other upload — no separate
  "supplementary CBOM" slot exists; prefer embedding the CBOM in a real SBOM, a dedicated product, or
  the Unassigned bucket if you need the CBOM and the regular SBOM to coexist.
  `/sbom-quality` (+ `/{id}`) (M1h — NTIA minimum-elements quality findings per `(product,
  lifecycle-stage slot)`, or per Unassigned-bucket SBOM; not part of `/actionable`). No new upload
  endpoint either — every SBOM is scored 0-100 inline at ingest (supplier/name/version/unique-ID/
  dependency-relationship per-component coverage, plus document-level author/timestamp, equal
  weight, floor-rounded); the per-document score rides on `GET /products`' `sboms[].quality`, and a
  finding is raised only when a slot's current SBOM scores below 70. Dependency relationship is
  checked for PRESENCE only (a component's bom-ref appears in a declared dependency edge) — it does
  not build or validate the real dependency graph (M1l's job).
  `/actionable` (+ `/{id}`) gained a per-row `riskScore`, an `?minScore=` filter and an `?rankBy=EPSS|SCORE`
  secondary-sort param (M1i — Scoring engine rework; `EPSS` stays the default, `SCORE` is opt-in), plus
  `riskScoreBreakdown` on the detail response. New: `GET /products/{id}/risk-score` and
  `GET /assets/{id}/risk-score` (the maximum score among that scope's default `/actionable`
  vulnerability population, plus `topFindingId`/`compromiseFindingCount`), `GET /risk-score/model`
  (the active `ScoringWeights`), `POST /risk-score/rescore` (queues the singleton `RISK_RESCORE` job —
  backfill/model-version bumps; no enrichment side effects). The score never gates `actionable`/
  `actionableReason`, and is null on a compromise row (never scored) or a not-yet-scored alert.
  `GET /findings` (+ `/types`, `/{type}/{id}`) (M1j — Finding & Action-item model): a read-model typed
  union over the five existing finding tables — vulnerability/compromise/lifecycle-drift/quantum-
  vulnerable/sbom-quality, plus a `PROVENANCE` stub with no data until M4 — never a new table, never
  touching `/actionable`; shows NOT_AFFECTED/RESOLVED rows with their derived `status` instead of
  hiding them. `/action-items` (+ `/{id}`, `PATCH /{id}`, `POST /{id}/findings`,
  `DELETE /{id}/findings/{type}/{findingId}`, `POST /{id}/comments`, `GET /{id}/history`): the
  concrete remediation task over one or more findings, scoped to exactly one product or asset
  (derived from its findings, never client-supplied); status machine OPEN/IN_PROGRESS/RISK_ACCEPTED/
  RESOLVED with derived NOT_AFFECTED (all linked active findings VEX not-affected), auto-reopen (a
  resolved item's finding reappears) and risk-acceptance expiry, all computed on read, never a cron
  job. `TriageState` is unchanged and never written by any of this. `/action-items` and `/findings`
  (M1k — Role-based views) both gained `?ownedBy=me|<uuid>`: restricts to product-scoped rows that
  user owns (asset-scoped rows always excluded); omit for no restriction, which both endpoints'
  default is — **no enforcement anywhere in M1k**, `GET /action-items` without `ownedBy` still shows
  everything. `ActionItemResponse`/`ActionItemDetailResponse` gained a computed `fixSummary`
  (remaining findings with/without a known fix), and every `FindingResponse` gained a `fix` block
  (`FindingFixAdvisor` — data-derived for `VULNERABILITY` off `fixState`/`fixedVersions`/`fixSource`,
  fixed templated guidance for the other four types). New: `GET /me/access` (which views —
  `LEADERSHIP`/`SECURITY_ENGINEER`/`SOFTWARE_ENGINEER` — the caller may pick; stateless, no
  current-view state anywhere server-side), `GET /me/owned-products`, `GET /tenant/members` (open to
  any authenticated user) and `PATCH /tenant/members/{userId}` (sets `roles`/`resetRolesToDefault`/
  `tenantAdmin` — **the one deliberate enforcement point in all of M1k**: 403 unless the caller is an
  effective tenant admin, i.e. `membership.tenantAdmin` or global `Role.ADMIN`). `POST
  /vex/statements` (author a TENANT-origin VEX statement directly, closing the one real
  security-engineer gap — `?origin=`/document-upload was the only way before) and `POST
  /action-items/{id}/disputes` (a dispute IS one of those statements, authored on the caller's
  behalf and run through the same M1f ingestion pipeline — no new review mechanism) both return 202
  with a `VEX_UPLOAD` job to poll. `GET /metrics/leadership` (aggregates only, no finding rows,
  `?mttrWindowDays=` default 90): severity/currentRisk reuse `ActionableService`'s exact
  `/actionable` vulnerability population (deliberately not `/stats/dashboard`'s, which has always
  ignored VEX/triage/lifecycle), `openFindingsByType` agrees with `/findings?type=X` by
  construction, `riskTrend.available` is always `false` (no score-history snapshot table exists),
  `mttr` is action-item-only with honest reopen/derivation caveats, `sbomStageCoverage` excludes the
  Unassigned bucket. `/actionable` does **not** hide risk-accepted items (closes M1j's deferred
  question) — `/action-items` already hides `RISK_ACCEPTED` by default, which is the right layer
  for that.
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
