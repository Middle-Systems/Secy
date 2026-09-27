# Database migrations

Schema changes are managed by [Liquibase](https://docs.liquibase.com/). Hibernate no longer owns the
schema: `spring.jpa.hibernate.ddl-auto=validate`, so the entity model is checked against whatever
Liquibase built, and a mismatch fails startup instead of silently altering tables.

## Layout

```
db/changelog/
  db.changelog-master.yaml   <- includeAll over changes/ — DO NOT EDIT to add a migration
  changes/
    001-baseline.sql         <- schema as of the ddl-auto=update era
    002-....sql              <- your changeset goes here
```

`db.changelog-master.yaml` uses `includeAll`, so **every file dropped in `changes/` is picked up
automatically**. Adding a migration means adding one new file — never editing the master changelog.
That keeps parallel branches from colliding on a shared file.

## Naming convention

`NNN-short-description.sql` (or `.yaml`)

- `NNN` — a zero-padded three-digit sequence number, unique across the directory.
- `short-description` — lowercase, hyphen-separated (`002-auth-users`, `003-ingestion-queue`).
- `includeAll` sorts files by name, so the zero-padding is what guarantees execution order.
  `010-*` must not become `10-*`.

Claimed prefixes:

| Prefix | Owner |
|--------|-------|
| `001`  | baseline schema (this branch) |
| `002`  | auth |
| `003`  | ingestion queue |
| `004`  | actionable enrichment on `vulnerability_alert` (Phase 1) |
| `005`  | `cve_exploit` — merged public exploit index (Phase 1) |
| `006`  | OSV mirror + CPE version ranges + CVE-5.1 fields + alert confidence/lifecycle (Phase 2) |
| `007`  | `sbom_component.identity_key` — product-stable component identity + widened `purl` (Phase 3) |
| `008`  | `sbom.pending_raw_body` / `sbom.job_id` for the SBOM_UPLOAD job queue + narrowed `uq_ingestion_job_active_type` (Phase 3) |
| `009`  | `asset` / `asset_component` / `asset_declared_cpe` + `vulnerability_alert.asset_component_id` with its XOR check + ASSET_SCAN excluded from `uq_ingestion_job_active_type` (Phase 4) |
| `010`  | `docker_compliance_report.asset_id` + job-queue columns + control pass/fail/skip counts, new `docker_compliance_control`, misconfig `status`/`check_id`/`control_id`, report-vulnerability identity fix, drops the dead `docker_vulnerabitity_alert` / `docker_misconfiguration_alert` tables, COMPLIANCE_SCAN excluded from `uq_ingestion_job_active_type` (Phase 5) |
| `011`  | `malicious_package` (+ `_version`, `_range`), `malware_hash`, `sbom_component_hash` / `asset_component_hash`, `compromise_finding` with its own XOR check, and `ingestion_job.type` widened to `varchar(32)` for `MALICIOUS_PACKAGES` (Phase 6) |
| `012`  | `kev.description` / `required_actions` / `notes` widened `varchar(1024)` → `text` — a real KEV ingest overflowed the cap on CISA's free-text prose |
| `013`  | `source_connector` + `source_connector_repo_allowlist`, `CONNECTOR_SYNC` excluded from `uq_ingestion_job_active_type` (Phase 6b) |
| `014`  | `triage_state` / `snoozed_until` / `assignee_id` on `vulnerability_alert` and `compromise_finding` + new `triage_event` append-only history table, with its own XOR check (Phase 7) |
| `015`  | `nvd_ingest_cursor` (NVD incremental ingest high-water mark) + indexes for the ingest write path and the CPE-join/dashboard read paths |
| `016`  | `nvd_ingest_cursor.oldest_swept_modified_date` — the backward-bootstrap sweep's own frontier |
| `017`  | `ingestion_job.last_progress_at` — heartbeat the stale-job reaper checks instead of total running duration |
| `018`  | `tenant` + `tenant_membership` (backfilled for every existing account) + `tenant_id` on `products`, `sbom`, `asset`, `vulnerability_alert`, `compromise_finding`, `source_connector`, `docker_compliance_report` (backfilled onto one default tenant), replacing the old global `products.name` and `asset (type, name)` uniqueness with tenant-scoped equivalents — schema only, no enforcement yet (ROADMAP.md, M0 — "Tenancy foundation") |
| `019`  | `product_tag_config` (per-tenant product tag key, seeded with the default `secy:product`) + `products.unassigned` / `products.tag_value` (with a partial unique index keeping one Unassigned bucket per tenant) + a backfilled Unassigned-bucket product per existing tenant (ROADMAP.md, M1a — "Tag-driven products") |
| `020`  | `ownership_link` — manual (M1b) and future inferred (M2/M3) ownership links from a product (asset from M3) to a registered user or a free-text principal/team, with its one-target and owner-shape XOR checks and per-`(target, owner, source, inference_method)` partial unique indexes (ROADMAP.md, M1b — "Ownership model") |
| `021`  | `sbom_component_identifier` (declared CPE/SWID per component instance) + `sbom_component.identity_confidence` + `sbom_component_identity_conflict` (one row per detected identifier conflict, its `other_component_id`/`other_identity_key` pair-or-neither check) + `sbom.ingestion_source` / `source_connector_id` (FK, `on delete set null`) / `lifecycle_stage` (reserved for M1e, unwritten) (ROADMAP.md, M1c — "Canonical component identity") |
| `022`  | Apache AGE extension + `secy_lineage` graph, both precondition-guarded (`onFail:CONTINUE`) so a Postgres without AGE still boots; labels/indexes are created at rebuild time (ROADMAP.md, M1d) |
| `023`  | `idx_sbom_product_stage_active` (lookup index for the per-(product, lifecycle stage) active-SBOM slot) + `lifecycle_drift_finding` — one row per (product, adjacent stage pair, drift kind, component identity) from the Source/Build/Analyzed/Deployed diff engine, reconciled like `compromise_finding`, no triage/severity columns (ROADMAP.md, M1e — "SBOM lifecycle stages + diffing") |
| `024`  | `vex_precedence_config` (per-tenant `VexPrecedencePolicy`, seeded default for existing tenants) + `vex_document` / `vex_statement` (OpenVEX/CSAF-subset/CycloneDX VEX documents and the statements parsed from them, never deleted) + `vulnerability_alert.vex_*` denormalized resolution snapshot + `VEX_UPLOAD` joining the per-invocation job types excluded from `uq_ingestion_job_active_type` (ROADMAP.md, M1f — "VEX ingestion") |
| `025`  | `sbom_component_crypto_asset` (1:1 CycloneDX 1.6 `cryptoProperties` subset per `cryptographic-asset` `sbom_component`, `relatedCryptoMaterialProperties.value` never stored, plus its ingest-time Shor-vulnerability classification) + `quantum_vulnerability_finding` (one row per `(product \| scope SBOM, crypto identity)` classified `VULNERABLE`, its two partial unique indexes, reconciled like `lifecycle_drift_finding`, no triage/severity) (ROADMAP.md, M1g — "CBOM ingestion") |
| `026`  | `sbom_component.supplier_name` + `sbom.document_timestamp` / `document_authors` / `quality_*` (NTIA minimum-elements completeness score and breakdown, null = not scored) + `sbom_quality_finding` (one row per `(product, lifecycle-stage slot)` — or per Unassigned-bucket SBOM — scored below the quality threshold, its two partial/expression unique indexes, reconciled like `quantum_vulnerability_finding`, no triage/severity) (ROADMAP.md, M1h — "SBOM quality scoring") |

Pick the next free number if yours isn't listed.

### Precondition-guarded changesets

`022` is the first changeset in this repo to use `--preconditions onFail:CONTINUE`. Every prior
migration assumes the server it runs against supports whatever it does — reasonable when the
changeset only uses core Postgres features. `022` is different: `create extension age` and
`ag_catalog.create_graph(...)` only exist once the Apache AGE extension is installed on the
server, which is an operator action outside Liquibase's control (see `api/docker/postgres-age/`
and `api/compose.yaml`), and plenty of real Postgres instances running this codebase will never
have it. `onFail:CONTINUE` lets those changesets skip themselves (with a logged warning) instead
of failing startup, and Liquibase re-attempts a skipped changeset on every subsequent boot — so
installing AGE later on an existing database is enough; no manual `changelog-sync` step needed.

## Writing a changeset

Formatted SQL files need the header and at least one changeset directive:

```sql
--liquibase formatted sql

--changeset secy:002-auth-users
create table app_user (...);

--rollback drop table if exists app_user;
```

Rules of thumb:

- Author id is `secy`; changeset id matches the file's `NNN-description`.
- One logical change per changeset; add a `--rollback` where a sensible inverse exists.
- **Never edit a changeset that has shipped.** Liquibase checksums applied changesets and a modified
  one fails on startup. Correct it with a new numbered file.
- Target dialect is PostgreSQL (see the testing note below).

## Baseline

`001-baseline.sql` was generated from the JPA entity metamodel with the PostgreSQL dialect
(`jakarta.persistence.schema-generation.scripts.action=create`) and hand-reviewed. It reproduces the
20 tables Hibernate had been creating under `ddl-auto=update`.

A database that already ran under `ddl-auto=update` **already has these tables**. Mark the baseline
as applied rather than running it:

```bash
liquibase --changelog-file=db/changelog/db.changelog-master.yaml changelog-sync
```

A fresh/empty database just applies it on first boot.

## Testing

Tests run against H2 with `spring.liquibase.enabled=false` and
`spring.jpa.hibernate.ddl-auto=create-drop` (see `src/test/resources/application.properties`) — the
schema under test is built by Hibernate from the entities, not by Liquibase. That keeps the test
suite fully offline and lets the changesets stay Postgres-dialect (`float4`, `uuid`, `timestamp(6)`,
quoted `"group"`), which H2 would not accept verbatim.

Gotcha: `src/test/resources/application.properties` **replaces** `src/main/resources/application.properties`
outright — it does not merge with it. Spring resolves `classpath:application.properties` to the first
match on the classpath, and test resources come first, so any main-profile-only key reads back as
`null` under test. If you add a property to the main file that your `@SpringBootTest` needs, add it
to the test file too.

The consequence: **the changelog itself is not exercised by `./gradlew test`.** Verify it against a
real PostgreSQL before merging — e.g. point `SECY_DB_URL` at a scratch database and boot the app, or
run `liquibase update` against it. `ddl-auto=validate` in the main profile is the safety net: if a
changeset and the entities disagree, the app refuses to start.
