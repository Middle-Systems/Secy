# Secy — Roadmap to v1

> Working document. Updated as milestones land. Pairs with `CLAUDE.md` (how the repo is laid
> out), the "Secy — Product Design Doc" (the product vision this roadmap now plans toward),
> and the session memory notes. Last revised 2026-09-24 — **this is a full rewrite**, replacing
> the earlier self-host-only, single-tenant MVP roadmap (see "What changed from the old
> roadmap" below). The old roadmap's Phases 1-7 are not discarded — they're the substrate this
> plan builds on.

## What Secy is now aiming to be

**A software supply-chain security platform.** It correlates what a tenant declared, built,
and deployed into one picture — SBOMs at every lifecycle stage, VEX statements, dependency
graphs, cryptographic assets — then tells each role which risks matter and what to do about
them. The core bet is correlation across the lifecycle: a CVE moves from "exists in a library
somewhere" to "running in prod, not VEX'd out, on KEV, high EPSS, owned by team X"
automatically, and every score is explainable.

Deployment target is **multi-tenant SaaS by default, plus a self-hosted edition** — the
reverse emphasis from the old roadmap, which was self-host-first with multi-tenancy explicitly
post-MVP.

### What changed from the old roadmap

| | Old roadmap (Phases 1-10) | New roadmap (M0-M4) |
|---|---|---|
| Delivery model | Self-host OSS first, single tenant, multi-tenancy post-MVP | Multi-tenant SaaS by default + self-hosted edition, tenant-aware from M0 |
| Product | Manually created, name + description | Tag-driven (`secy:product=...`), configurable tag key, "Unassigned" bucket |
| Ownership | None | Inferred (CODEOWNERS, team perms, cloud tags) + manual override, source tracked |
| Component identity | PURL-primary `identityKey` (Phase 3) | Same PURL-primary base, formalized with CPE/SWID/hash as secondary identifiers and confidence-flagged conflicts |
| Lineage | None | Graph DB (Apache AGE on Postgres) for lifecycle → component → finding → action-item edges |
| SBOM stages | None — one SBOM per product | Source / Build / Analyzed / Deployed, tagged at ingestion, diffed for drift findings |
| VEX | Backlog item ("extends Phase 7") | In M1: CycloneDX VEX, OpenVEX, CSAF, configurable precedence |
| CBOM (crypto assets) | Not planned | In M1: CycloneDX 1.6 crypto assets, quantum-vulnerable algorithm flagging |
| Alert model | `VulnerabilityAlert` / `CompromiseFinding`, `TriageState` (ack/snooze/resolve/false-positive) | Broader `Finding` (vuln, drift, quantum-vuln, provenance, SBOM quality) + `ActionItem` grouping; status machine reconciled with the existing one |
| Views | One view, ADMIN role only | Three role-based views (leadership / security engineer / software engineer) over one data model |
| Connectors | GitHub (PAT) / AWS / Azure (static creds), agentless SBOM/scan pull only | Same providers, upgraded to GitHub App + cross-account IAM/workload-identity, plus ownership inference, plus Kubernetes + registry connectors |
| Security of Secy | Not addressed as its own concern | Tenant isolation (RLS), per-tenant KMS-encrypted secrets, SSO, audit log — own hardening milestone |
| Feeds | 8 feeds, all already shipped | Unchanged — reused as-is, just gain per-tenant toggles |

The **8 feeds already in the codebase answer the design doc's own open question** ("which
feeds exist today?"): NVD, KEV, EPSS, OSV, CVE List v5 + CISA Vulnrichment, an exploit index
(merged Nuclei templates + Metasploit modules + PoC-in-GitHub), OpenSSF Malicious Packages, and
abuse.ch MalwareBazaar. No new feed engineering is needed for M1 — only per-tenant enable/
disable toggles and score-snapshot semantics.

### Decisions locked in (2026-09-24)

| Question | Decision |
|---|---|
| Tenancy sequencing | **Schema now, enforcement later.** `Tenant` + `tenant_id` land in M0 on every table the roadmap touches. Postgres row-level security, per-tenant KMS, SSO, and the audit log are a dedicated **Tenancy hardening** milestone, not M0 — M1 runs functionally as a single implicit tenant. |
| Graph DB | **Apache AGE on Postgres.** No second stateful service, no Helm-chart addition for self-host, one backup/restore story, trivially rebuildable from Postgres (the system of record) as the design doc requires, no dependency on one cloud's managed graph service (rules out Neptune). |
| Prior work | **Reuse as substrate.** `VulnerabilityAlert`, `CompromiseFinding`, `CorrelationService`, all 8 feeds, and the GitHub/AWS/Azure connectors are kept and extended, not rewritten. New work is scoped as deltas. |
| Products | Tag-driven, tag key configurable per tenant — **default `secy:product`, locked in M1a**. Untagged assets land in "Unassigned". Manual product assignment at upload time stays available until connectors exist. |
| Component identity | PURL is the primary key; CPE, SWID, and content hashes are secondary identifiers. Conflicting identifiers flag a low-confidence link rather than guessing. |
| VEX precedence | Configurable per tenant; default is tenant statements override vendor statements, conflicts flagged for review. |
| Risk acceptance approval | **Still open** — the design doc leaves this unresolved (security-engineer approval vs. owner self-accept) and it's a policy call, not an engineering one. Decide before M1j (the Finding/Action-item status machine) ships the risk-acceptance flow. |
| Test fixtures | Synthetic fixtures, extending the existing `api/src/test/resources/correlation/` golden-set pattern already used for correlation precision/recall testing — repeatable, no anonymized-real-SBOM sourcing problem. |
| Capacity | Unchanged — solo + Claude sessions, milestone-paced, no hard date. |

---

## Current state (baseline going into M0)

Everything below is real, shipped code on `feat/phase-1-actionable-core` (**not merged to
`master`**) that the new roadmap builds on rather than replaces. See the design-doc mapping
table above for what's reused as-is vs. extended.

**Backend (`api/`)** — Spring Boot 3.3, Java 17, PostgreSQL, Liquibase (changesets `001`-`014`),
OpenAPI.
- **Funnel**: `VulnerabilityAlert` enriched with KEV/EPSS/exploit-maturity/fix-state;
  `actionable` = KEV OR EPSS > threshold OR has a `CompromiseFinding`. `GET /actionable` is a
  typed union of vulnerability + compromise rows.
- **Correlation**: `CorrelationService`, OSV-primary with CPE-range fallback, per-ecosystem
  `VersionScheme`, `matchConfidence`, alert lifecycle (auto-resolve/no-dupes), a 6-fixture
  golden set at precision/recall ≥ 1.0.
- **Feeds** (8, all job-queued, manual-trigger only today): NVD, KEV, EPSS, OSV, CVE List v5 +
  Vulnrichment, exploit index, OpenSSF Malicious Packages, abuse.ch MalwareBazaar.
- **SBOM**: `NormalizedComponent` shared CycloneDX/SPDX parse target, version-less-PURL
  `identityKey` survives re-upload, job-queued upload with progress polling.
- **Assets**: `Asset`/`AssetComponent` (CONTAINER_IMAGE/HOST/SERVICE), Trivy + Grype JSON
  ingest, scanner-reported fix versions.
- **Compliance**: Docker/CIS reports route through the same `Asset` pipeline as scanner ingest;
  misconfigurations get their own control-breakdown model (deliberately outside the CVE funnel).
- **Compromise detection**: `CompromiseFinding` (own table), malicious-package + malware-hash
  matching, IOC aging.
- **Connectors**: `SourceConnector` (GITHUB/AWS/AZURE), one instance-wide credential per
  provider, agentless sync through the same `AssetService#applyScan` / SBOM ingest paths as
  manual upload.
- **Triage**: `TriageState` (OPEN/ACKNOWLEDGED/SNOOZED/RESOLVED/FALSE_POSITIVE) + `assignee` +
  append-only `TriageEvent` history on both alert types, bulk actions, `PATCH /actionable/{id}`.
- **Auth**: single-tenant JWT, first registered user → ADMIN. `User`/`Role` only — no `Tenant`
  entity, no row-level scoping anywhere in the schema today.
- **Product**: `id` / `name` / `description` / `sboms` only — no tags, no ownership, no
  lifecycle-stage concept on `SBOM`.

**Frontend (`ui/`)** — React 18, Vite 6, TanStack Router/Query/Table, Tailwind + shadcn.
Actionable Items (index), Dashboard, KEV/EPSS/CVE browsers, Product Catalog, Infrastructure,
Compliance, Connectors settings — one view, no role differentiation.

**Known gaps the new roadmap must close** (superset of the old roadmap's list, most of the
original 10 are now closed):
1. No `Tenant` concept anywhere — everything is implicitly single-tenant.
2. `Product` has no tags, no ownership, is manually created only.
3. No SBOM lifecycle stage — one upload replaces/adds to a product's component set with no
   source/build/analyzed/deployed distinction, so lifecycle drift can't be detected.
4. No VEX ingestion — `not_affected`/`fixed`/`under_investigation` statements aren't modeled.
5. No CBOM / cryptographic-asset ingestion, no quantum-vulnerable-algorithm flagging.
6. No graph DB — blast-radius and lineage queries aren't possible today.
7. `NormalizedComponent` identity has no CPE/SWID/hash secondary resolution or
   confidence-flagged conflict handling.
8. Connectors use static, instance-wide credentials, not a GitHub App or cross-account
   IAM/workload-identity model; no Kubernetes or registry connector; no ownership inference.
9. One role (ADMIN) — no leadership/security-engineer/software-engineer view split.
10. `TriageState` doesn't have risk-acceptance-with-expiry or a VEX-backed not-affected status,
    and doesn't auto-reopen when a resolved component reappears.
11. No Postgres row-level security, no per-tenant secret storage, no SSO, no audit log.
12. No Helm chart for self-hosted multi-tenant-capable deployment.

---

## Milestones

Each milestone is independently shippable and leaves `master` green
(`cd api && ./gradlew build`; `cd ui && npm run build && npm test`).

### M0 — Tenancy foundation (schema only)
*Goal: nothing built from here on needs a tenancy retrofit.*

**Status: SHIPPED.** `Tenant` + `TenantMembership` (explicit many-to-many join, not a bare
`@ManyToMany`) landed, along with a `TenantOwnedEntity` mapped superclass that `Product`, `SBOM`,
`Asset`, `VulnerabilityAlert`, `CompromiseFinding`, `SourceConnector` and `DockerComplianceReport`
now extend. Migration `018` creates `tenant`/`tenant_membership`, adds `tenant_id` to all seven
tables, backfills everything onto one default tenant, and replaces the old global
`products.name`/`asset (type, name)` uniqueness with tenant-scoped equivalents. Every new user
joins the default tenant on registration. `tenant_id`/`tenant` are `@JsonIgnore`d, so neither
appears in a response nor can be set by a client. No enforcement, tenant CRUD, tenant switching, or
per-tenant roles yet — that's Tenancy hardening, still ahead.

- **`Tenant` entity**: id, name, slug, created-at. `User` gains a tenant membership (many-to-many
  if a user can belong to more than one tenant — decide during implementation; the design doc's
  "a user can hold more than one role and switch views" is per-tenant, not cross-tenant).
- **`tenant_id`** added to every table this roadmap touches: `Product`, `SBOM`, `Asset`,
  `VulnerabilityAlert`, `CompromiseFinding`, the future `Finding`/`ActionItem`, `SourceConnector`,
  and any new M1 tables (products-by-tag config, ownership links, VEX statements, CBOM findings).
  Feed tables (`kev`, `epss`, `osv_advisory`, etc.) stay tenant-agnostic — they're global
  intelligence, not tenant data.
- **Migration**: backfill one default tenant for all existing rows so the branch keeps working
  single-tenant through M1 without every query needing a tenant filter yet.
- **Explicitly not in scope**: Postgres row-level security enforcement, per-tenant KMS, SSO,
  audit log — see **Tenancy hardening** below. `tenant_id` existing on a row is not the same as
  it being enforced; M0 just stops the schema from needing a second migration pass later.

### M1 — Ingestion core to action items
*Goal: the design doc's M1 — SBOMs at every lifecycle stage, VEX, CBOM, canonical identity,
scoring, findings/action items, and all three role views, with no external integrations yet.*

This is the bulk of the new work. It's broken into lettered sub-phases so it can ship
incrementally rather than as one giant branch; the dependency order below is a starting
suggestion, not a hard requirement.

**M1a — Tag-driven products.** Configurable tag key (default `secy:product`, per-tenant
override — see the open decisions table). Anything untagged lands in an "Unassigned" bucket
visible to security engineers. Manual product assignment at SBOM-upload time stays as the path
until M2/M3's connectors exist to apply tags automatically.

**Status: SHIPPED.** `product_tag_config` (one row per tenant, default `secy:product`, migration
`019`) plus `products.unassigned` / `products.tag_value` land the real pieces: a per-tenant
Unassigned-bucket `Product` row (backfilled for every existing tenant, lazily created for a new
one), `ProductTaggingService.resolveProduct(tenantId, tags)` as the single resolution seam, and a
tag-driven `POST /sbom` upload (repeated `tag=key=value` params) alongside the unchanged manual
`POST /sbom/{productId}/sboms` path. The bucket is a first-class catalog row — all of its SBOMs
stay active and correlate/detect at their own SBOM scope rather than the whole-product scope a
normal product uses, it can't be deleted or renamed, and `ProductRepository` is closed to Spring
Data REST's default CRUD. `GET`/`PUT /settings/product-tagging` exposes the tag key.
**Stubbed for M2/M3, comment-only `TODO`s, no behavior change**: GitHub repo topics/custom-
properties, AWS/Azure resource tags, and CycloneDX/SPDX property parsing — none of these
automatically call `resolveProduct` yet; only the manual upload path does. No tag-key-editing UI
and no role gating (M1k) either.

**M1b — Ownership model.** Manual mapping only in this sub-phase — inference needs M2/M3's
connectors (CODEOWNERS, GitHub team permissions, cloud resource tags). Each ownership link
records its source (`INFERRED` / `MANUAL`) even though only `MANUAL` is populated yet, so M2/M3
don't need a schema change to add inference.

**Status: SHIPPED.** `ownership_link` (migration `020`) links a target — a `Product` today, an
`Asset` from M3 on (the `asset_id` column exists now so M3 needs no later migration, but nothing
writes it yet) — to an owner: a registered `User`, or a free-text `principal` (an unregistered
individual's GitHub login/email, or a team name), typed by `owner_type` (`USER`/`TEAM`). Many-to-
many: a product can have several owners, a user or team can own several products, and a `MANUAL`
and an `INFERRED` link for the same owner can coexist (manual intent survives an inference
refresh) — enforced by a per-`(target, owner, source, inference_method)` partial unique index.
`OwnershipService`/`ProductOwnershipController` expose `GET`/`POST /products/{id}/owners` and
`DELETE /products/{id}/owners/{ownerId}` for `MANUAL` links only; a manual `USER` link must
reference a registered, enabled tenant member, a manual `TEAM` link takes free text only, and the
Unassigned bucket can't have owners (409). `source`/`inference_method` (`CODEOWNERS`/
`GITHUB_TEAM_PERMISSION`/`CLOUD_RESOURCE_TAG`) are reserved for M2/M3's writers via comment-only
`TODO`s next to `GitHubSyncService.findOrCreateByName`, `AwsSyncService` and `AzureSyncService` —
no inference runs yet. No ownership UI and no role gating (M1k) either.

**M1c — Canonical component identity.** Extend the existing `NormalizedComponent`/`identityKey`
(PURL-primary, built in the old roadmap's Phase 3) with CPE, SWID tag, and content hash as
secondary identifiers. When identifiers conflict across sources, flag the link low-confidence
instead of guessing a merge. Keep per-instance provenance (which SBOM, which stage, which
ingestion) — already partially present, formalize it as a first-class field.

**Status: SHIPPED.** `identityKey` and its computation (`ComponentIdentity.keyOf`, PURL-primary,
no secondary identifier ever folds into it) are unchanged — re-keying onto a declared CPE/SWID
would orphan every alert already carried forward under the old key. CPE and SWID are new declared
secondary identifiers, persisted one row per identifier in `sbom_component_identifier` (migration
`021`, SBOM-only — asset-side is a future M3 table) with the exact document field each came from
(`cyclonedx:component.cpe`, `spdx:externalRefs.cpe23Type`, …); content hashes stay exactly where
they already were (`sbom_component_hash`, Phase 6) and are read, not duplicated. Two conflict
passes run at ingestion, inside `SBOMService.ingestDocument`'s transaction, never at correlation
time: `ComponentIdentityAssessor` (pure, no Spring/JPA) checks one component's own declared
identifiers against its primary identity by name-token overlap (not string equality — PURL and CPE
naming conventions differ systematically) and version agreement, and flags two hash entries under
the same canonical algorithm disagreeing; `ComponentIdentityService.flagHashIdentityCollisions`
then sweeps the same strong content digest (MD5/SHA-1 and well-known empty-content digests
excluded) across every other component in the tenant, both sides flagged, never merged. Either
pass can set `sbom_component.identity_confidence` (`CORROBORATED` / `UNCORROBORATED` /
`CONFLICTING`, null = not assessed) and add a `sbom_component_identity_conflict` row per detected
disagreement, readable via `GET /sbom/{sbomId}/components/{componentId}/identity`.
**`IdentityConfidence` is orthogonal to `MatchConfidence`** — a per-component, CVE-independent
document-facts judgment versus a per-(component, CVE) alert value; M1c does not cap or otherwise
influence `MatchConfidence`, and the correlation engine's matching logic, `ComponentCoordinate`,
`CpeMatcher`/`OsvMatcher`/`CorrelationMatch`, and the golden test set are all unchanged (precision/
recall still 1.0 across every fixture). Per-SBOM provenance is formalized on `sbom`:
`ingestion_source` (`MANUAL_UPLOAD` / `TAGGED_UPLOAD` / `GITHUB_CONNECTOR`, set by whichever
`SBOMService.createPlaceholder` caller created the row) and `source_connector_id` (a plain id, not
an association, `on delete set null`). **`lifecycle_stage` exists on `sbom` now, nullable, and
nothing in M1c writes it** — reserved for M1e, following M1b's no-retrofit precedent so M1e needs
no further migration. **Not done, deliberately**: a declared CPE does not yet feed
`PurlCpeBridge`'s vendor/product guess (would change alert sets/confidence, needs its own golden
fixtures — tracked as a `TODO(post-M1c)`); CycloneDX 1.6 `evidence.identity`/`omniborId`/`swhid`/
nested `components[].components[]` are not parsed (noted as a follow-up, not built).

**M1d — Lineage graph (Apache AGE).** Stand up Apache AGE as a Postgres extension (no new
service). Write lineage edges Product → Repo → Build → Image/Artifact → Workload/Cloud Asset,
and Build → Component (PURL) → Vulnerability → Finding → Action item, mirroring the design
doc's `flowchart LR`. Graph writes are derived from Postgres and must be rebuildable from it —
Postgres stays the system of record, the graph is a queryable index over it, not a second
source of truth.

**Status: SHIPPED (unverified against live AGE).** Implemented as a rebuild-from-Postgres job
(`POST /lineage/rebuild`), not live incremental sync (a follow-up). This devcontainer has no
Docker and cannot run Postgres or the AGE extension, so the split below is deliberate and the
honest state of things:

- **(A) Real, tested here** (pure logic + H2, exercised by `./gradlew test`): the planner
  (`LineagePlanner` — Postgres rows → nodes/edges, with the exact scope rules: active SBOMs only,
  root/metadata component excluded, present-in-last-scan-only asset components), the Cypher
  renderer (`CypherRenderer`/`AgeSql` — exact statement text, chunking, ordering), the JPA source
  reader (`LineageSourceReader`, runs fine on H2 since it's plain JPQL), the rebuild orchestration
  (`LineageRebuildService`, tested via an in-memory fake `LineageGraphWriter`), `LINEAGE_REBUILD`
  job dispatch + `POST /lineage/rebuild` + config wiring, and the `ReEnrichmentListener` exclusion.
- **(B) Real code, only user-verifiable** (cannot run here, needs a live Postgres + AGE): migration
  `022` (precondition-guarded so a Postgres without AGE still boots), `AgeLineageGraphWriter`'s
  actual `ag_catalog.cypher()` JDBC execution, and the `api/docker/postgres-age/` Docker image
  change. An opt-in integration test (`AgeLineageGraphWriterIT`, gated on `SECY_AGE_IT_URL`) exists
  for whoever next has Docker/Postgres access to run — see `api/README.md`'s runbook.
- **(C) Explicitly deferred, not built**: live incremental sync, Repo nodes, Build nodes (SBOMs are
  labeled `SBOM`, not invented as `Build`, until M1e/M3 land real build entities), Build→Image /
  Image→Workload edges, Finding/ActionItem nodes (M1j), Owner nodes (M2), dependency/root-component
  edges (M1l), any graph-read API or UI, RLS-equivalent tenant isolation at the AGE label-table
  level (Tenancy hardening), and scheduled/automatic rebuilds.

**M1e — SBOM lifecycle stages + diffing.** Every SBOM is tagged with its stage (Source / Build /
Analyzed / Deployed) at ingestion, by upload metadata or API field. A diff engine runs
automatically whenever a new SBOM for a stage arrives and a comparable SBOM exists for the
adjacent stage:
  - Source vs Build mismatch → possible dependency confusion / build injection finding.
  - Build vs Deployed mismatch → runtime drift / unauthorized change finding.
  - Build vs Analyzed mismatch → incomplete SBOM / tampering finding.

**Status: SHIPPED.** The pre-M1e "one active SBOM per product" invariant is now per-`(product,
lifecycle_stage)`: `SBOMService.createPlaceholder` deactivates every active SBOM of the incoming
stage (or every stage-less one, if the new upload declares no stage) rather than the whole
product, so a normal product holds either one active stage-less SBOM (legacy mode) or up to one
active SBOM per stage (staged mode) — the two never mix, and `null` still means "stage unknown",
never a default. No DB uniqueness constraint enforces this (the Unassigned bucket legitimately
holds many active SBOMs, and a partial index can't see `products.unassigned`); read paths use
`findFirst...OrderByUploadDateDesc` to tolerate a same-stage upload race. **Correlation/detection
scope changed to match**: `SbomCorrelationScope` gives a staged, product-scoped SBOM the union of
every active stage's components (ascending by `SbomLifecycleStage.downstreamRank()`), so
correlating one stage never auto-resolves another stage's alerts — the rule is now "most-
downstream current stage wins" for a shared component identity, not "last scan wins". Every
existing (stage-less) fixture is unaffected by construction. **How the stage is set**: the
`?stage=` param on both `POST /sbom/{productId}/sboms` and `POST /sbom` wins when given (400 on
an unrecognised value); otherwise CycloneDX 1.5+ `metadata.lifecycles[]` is mapped
(`pre-build`→SOURCE, `build`→BUILD, `post-build`→ANALYZED, `operations`→DEPLOYED; conflicting or
absent phases → null; SPDX has no equivalent, left as a `TODO(spdx-3)`); the GitHub connector
always writes SOURCE. **The diff engine**: a pure `LifecycleDiffer` classifies each of the three
adjacent pairs' downstream-vs-upstream disagreement as `UNEXPECTED_COMPONENT` or
`VERSION_MISMATCH` (a component present upstream but missing downstream is computed but never
raised — too noisy), scoped by ecosystem coverage so an app-only SBOM never gets flagged for OS
packages it never inventoried. `LifecycleDiffService` runs it from a synchronous
`@TransactionalEventListener(phase = AFTER_COMMIT)` on the existing `SbomUploadedEvent` — after
commit, not inline, so two concurrent stage uploads (the ingestion worker pool defaults to 2) each
see the other's committed components regardless of which one runs first; a diff failure is caught
and logged, never fails the ingestion job that triggered it. Findings land in their own
`lifecycle_drift_finding` table (migration `023`, plain UUID references per M1c's precedent,
reconciled with the same `AlertLifecycleState` ACTIVE/AUTO_RESOLVED lifecycle as
`VulnerabilityAlert`/`CompromiseFinding`, no triage/severity columns), browsable at
`GET /lifecycle-drift` and `GET /lifecycle-drift/{id}` — **deliberately not folded into
`GET /actionable`**, which ranks by KEV/EPSS/CVSS that a drift finding has none of. **Explicitly
deferred**: triage/severity (M1j/M1i), KEV-style ranking (M1i — the data precondition is in place:
`alert.component.sbom.lifecycleStage` already distinguishes a Deployed alert from a Source-only
one, pinned by `StagedCorrelationScopeTest`), lineage drift nodes (M1j), a drift-finding UI (M1k),
SPDX 3 lifecycle metadata, and a manual re-diff endpoint.

**M1f — VEX ingestion.** CycloneDX VEX (embedded or standalone), OpenVEX, and CSAF VEX parsers
into a `VexStatement` model: status (`not_affected` with justification, `affected`, `fixed`,
`under_investigation`), precedence resolved per the tenant's configured rule (default: tenant
overrides vendor, conflicts flagged for review). Every finding shows which statements applied
and which one won.

**Status: SHIPPED (CSAF: subset — product_tree leaves + one-hop relationships, PURL-only matching; whole-product statements stored but not applied).**

- **What shipped.** `POST /vex?origin=TENANT|VENDOR[&productId=]` validates synchronously, returning a 400 for a malformed document and a 413 over `secy.vex.max-document-bytes` (10 MB), with nesting-depth and duplicate-key limits. Nothing is queued on a rejection. The work then runs as a `VEX_UPLOAD` job.
- **Formats.** OpenVEX (0.2.0 and legacy 0.0.1) and CycloneDX VEX (1.4-1.6, standalone or embedded, bom-ref/BOM-Link/PURL refs) are parsed into `vex_statement` rows (migration `024`). Also accepted: a scoped subset of CSAF 2.0 (`csaf_vex`/`csaf_security_advisory`: branches, full_product_names, one-hop relationships, product_groups, product_status + flags + impact threats + remediations).
- **Resolution.** Each alert carries a `vex_status`/`vex_justification`/`vex_statement_id`/`vex_conflict` snapshot, resolved per tenant policy (`GET`/`PUT /vex/settings/precedence`, default `TENANT_OVER_VENDOR`). The newest statement per author supersedes that author's older ones. Disagreeing authors in the winning tier set `vex_conflict` and nothing wins.
- **Effect on `/actionable`.** `GET /actionable` hides NOT_AFFECTED/FIXED rows by default (`?vexStatus=`, `?vexConflict=`), and `GET /actionable/{id}` lists every applicable statement with its role (WON/AGREES/CONFLICTING/OVERRIDDEN/SUPERSEDED). `actionable`, `triageState` and the dashboard counts are deliberately untouched.
- **When statements apply.** Statements are stored independently of alerts and applied on VEX ingest, on every correlation (a statement that arrives before its component still applies), on document deactivation, on a policy change, and on `POST /vex/reconcile`.
- **Not done, deliberately:** CSAF relationship chains beyond one hop, platform scoping, `product_version_range`/vers, CPE and hash identification helpers, CSAF 2.1, signatures and ROLIE; CPE matching in any format, and CycloneDX `versions[].range`; whole-product statements applying to every component of a Secy Product; automatic extraction of embedded VEX from `POST /sbom`; VEX authoring/UI (M1k), the M1j status-machine integration, M1i scoring input, and role gating. A narrow race exists with a correlation running concurrently; it heals on the next correlation, the next VEX upload, or `POST /vex/reconcile`.

**M1g — CBOM ingestion.** CycloneDX 1.6 cryptographic-asset ingestion: algorithms, keys,
certificates, protocols. Quantum-vulnerable algorithms (RSA, ECC) become their own finding
category. Confirm the current CycloneDX parser's version ceiling during implementation — the
design doc requires 1.6 specifically for this.

**Status: SHIPPED.**

- **What shipped.** CBOM rides on the existing SBOM upload endpoints — no new upload endpoint. A
  `cryptographic-asset` component's `cryptoProperties` is extracted only when the document declares
  `specVersion >= 1.6` (`CycloneDxSpecVersion`, floor 1.6/ceiling major==1 — a skip below the floor,
  never a rejection); below it the component still ingests as a plain row. `cryptoProperties` is
  bound as a raw `JsonNode` (`CryptoPropertiesExtractor`), tree-walked leniently — malformed shapes
  degrade field-by-field rather than failing the upload, and `relatedCryptoMaterialProperties.value`
  is never captured, in the model or the sanitized JSON copy. Each extracted asset is classified for
  Shor-vulnerability (`QuantumVulnerabilityClassifier`, pure/static): OID first, then name patterns
  (PQC checked before Shor patterns so hybrids like `X25519MLKEM768` aren't flagged), then curve,
  then primitive/declared-NIST-level fallbacks — a name/OID match always overrides a declared level,
  surfaced as a contradiction note rather than trusted. Persisted 1:1 per component in
  `sbom_component_crypto_asset` (migration `025`, `@OneToMany` + a DB unique constraint, not
  `@OneToOne`, to avoid a bytecode-enhancement-dependent lazy load on every component read).
  `VULNERABLE` assets become `quantum_vulnerability_finding` rows (migration `025`), reconciled by
  `QuantumFindingService` from a synchronous `@TransactionalEventListener(AFTER_COMMIT)` on the
  existing `SbomUploadedEvent` — extraction/classification runs inline at ingest (no cross-document
  dependency, M1c's Pass A pattern), but finding reconciliation needs the same after-commit,
  staged-scope-union treatment `LifecycleDiffService` uses, since a finding must carry forward across
  re-uploads and a staged product's candidate set is the union of every active stage slot. Unlike
  M1e's drift engine, bucket (Unassigned) SBOMs get their own per-SBOM findings rather than being
  skipped, so a security finding doesn't vanish just because an upload was untagged. Never deleted,
  auto-resolved/revived exactly like `VulnerabilityAlert`/`LifecycleDriftFinding`. **Crypto components
  are excluded from vulnerability correlation, compromise detection, and M1e's lifecycle drift** — a
  false-positive hazard fixed as part of this milestone (a no-PURL crypto asset named "AES" or "RSA"
  would otherwise trip the heuristic CPE matcher or malware-name matching). Read-only API:
  `GET /cbom/assets[/{id}]` (inventory, never includes raw key material) and
  `GET /cbom/quantum-findings[/{id}]` — not part of `GET /actionable` (no KEV/EPSS/CVSS to rank by).
- **Not done, deliberately (D1-D8 in the implementation plan):** a separate "supplementary CBOM"
  slot — a standalone CBOM (every component crypto-typed) uploaded to a product replaces that
  product's/stage's whole active SBOM exactly like any other upload, auto-resolving its vulnerability
  alerts until a real SBOM is re-uploaded (a WARN is logged; recommended workarounds are: embed the
  CBOM in a real SBOM, use a dedicated product, or upload untagged to the Unassigned bucket); nested
  `components[].components[]` (existing parser limitation, all types); Grover-weakened
  symmetric/hash flagging (explicitly out of scope — this milestone only covers Shor-broken
  algorithms); classical weakness (RSA-1024, SHA-1, expired certs — data is captured for M1h/M1i but
  not flagged now); CycloneDX 1.7-only fields beyond the 1.6 set (raw JSON only, via
  `cryptoProperties` on the detail endpoint); pre-standard IBM CBOM (`"bomFormat": "CBOM"`, already
  rejected by the existing format check) and CycloneDX XML; SPDX 3 crypto (`TODO(spdx-3)`);
  triage/severity/scoring (M1j/M1i); `/actionable` integration and UI (M1k); lineage crypto/finding
  nodes (M1j); a manual re-reconcile endpoint; TLS 1.3 protocols whose key exchange is expressed only
  by name (classified `NOT_VULNERABLE` alone — a documented limitation, not a bug).

**M1h — SBOM quality scoring.** Score each ingested SBOM against the NTIA minimum elements
(supplier, name, version, unique ID, dependency relationships, author, timestamp). A low score
becomes its own finding category, surfaced per product.

**Status: SHIPPED.**

- **What shipped.** Every ingested SBOM is scored 0-100 against the seven NTIA minimum elements,
  computed inline in `SBOMService.ingestDocument` (`SbomQualityScorer`, pure/static, M1c's Pass A
  pattern — self-contained to the one document, no cross-SBOM dependency). Five are per-component
  coverage percentages over the document's non-crypto, root-excluded population (empty population —
  including a standalone CBOM — means "not scored", `quality: null`, not a score of zero): supplier,
  component name, component version, unique identifier (PURL/CPE/SWID/hash), and dependency
  relationship. Two are document-level all-or-nothing: author (tools never count) and the document's
  own declared timestamp (never `sbom.uploadDate`). All seven are equal-weight, exact-integer floored
  arithmetic — 100 means fully complete, never a rounded-up near-miss. New parsing added to support
  this, `JsonNode`-bound like M1g's `cryptoProperties` (a typed POJO would risk turning an
  already-accepted document into a 400): CycloneDX `component.supplier`, `metadata.authors[]`, 1.6
  `metadata.manufacturer` (1.5's `metadata.manufacture` and either format's product-supplier field are
  deliberately NOT read as an SBOM-author source), and top-level `dependencies[]`; SPDX's existing
  `PackageSupplier` binding is now read, plus `Person:`/`Organization:` `creationInfo.creators[]`
  entries and a fixed allowlist of dependency-style `relationships[].relationshipType`s (excluding
  `DESCRIBES`/`DESCRIBED_BY`, which identify the root, not an edge). The score is stored as an
  `@Embeddable` on `sbom` (migration `026`, every column a wrapper type so an unscored SBOM's row
  stays insertable), so `GET /products`' `sboms[].quality` carries it automatically, alongside a new
  `supplierName` on every component and `documentTimestamp`/`documentAuthors` on every SBOM. A score
  below 70 (`SbomQualityScorer.FINDING_THRESHOLD`, a constant — the test `application.properties`
  replaces rather than merges with the main one, so a `@ConfigurationProperties` field would need
  restating there; M1i is expected to make this tenant-configurable) becomes an
  `sbom_quality_finding` row, reconciled by `SbomQualityFindingService` from the same
  `SbomUploadedEvent` after-commit listener pattern as M1e/M1g. **Finding identity is the SLOT — 
  `(product_id, lifecycle_stage)`, null stage the legacy unstaged slot — or `scope_sbom_id` for the
  Unassigned bucket, one row per bucket SBOM — never the SBOM id**, so a re-upload of an equally-poor
  document revives the same row instead of losing triage continuity to a resolve/recreate cycle; an
  improved re-upload auto-resolves it, and superseded stage slots (an unstaged upload superseding
  every staged SBOM, or vice versa) are swept auto-resolved in the same reconcile pass. Unlike
  M1e/M1g, there is no cross-SBOM union or diff here — the candidate is always exactly the one SBOM's
  own score; the only other SBOMs ever read are the product's active-slot set, solely to sweep
  superseded slots. Read-only API: `GET /sbom-quality[/{id}]` — not part of `GET /actionable` (no
  KEV/EPSS/CVSS to rank it by).
- **Dependency relationship is checked for PRESENCE only.** `dependencyRelationshipRefs` records
  which bom-refs/SPDXIDs take part in at least one declared dependency relationship — it does
  **not** build or validate the dependency graph. That is explicitly M1l's job; this milestone never
  traverses edges, only checks whether a component's own bom-ref appears in the declared set (a
  component with no bom-ref automatically fails this element).
- **Not done, deliberately.** A manual rescore/re-reconcile endpoint; backfilling a score onto
  pre-M1h SBOMs (their raw bodies are already gone by the time this shipped — `pendingRawBody` is
  cleared at ingest); nested `components[].components[]` (existing parser limitation, all formats);
  SPDX `files[]`/`snippets[]`; CycloneDX XML/SPDX 3 dependency and author/supplier equivalents
  (`TODO(spdx-3)`); tenant-configurable weights/threshold (M1i); triage/severity and `/actionable`
  integration (M1j/M1i); UI (M1k); lineage finding nodes (M1j); NTIA's non-field "practices and
  processes" guidance; newer CISA fields (tool name, generation context, license, hash-as-a-separate-
  element).

**M1i — Scoring engine rework.** Scores exist at three levels — finding, asset, product — with
asset/product rolling up from their findings. Finding-score inputs: base CVSS severity,
exploitation signals (KEV, EPSS — already computed by the existing funnel), lifecycle presence
(source-only vs. confirmed-deployed, from M1e), VEX status (M1f), dependency depth (direct vs.
transitive, from M1l), fix availability (already tracked as `fixState`). Every finding shows a
per-input breakdown of how each signal moved the score. Weights live in one place so they can
become tenant-configurable later (future-expansion item, not M1 scope).

**M1j — Finding & Action-item model.** Broaden the alert model beyond `VulnerabilityAlert` /
`CompromiseFinding` to a `Finding` supertype covering: vulnerable component, lifecycle drift
(M1e), quantum-vulnerable algorithm (M1g), failed provenance check (stub until M4), and
low-quality SBOM (M1h). Add `ActionItem`: the concrete remediation task for one or more
findings, assigned to an owner — upgrades are grouped, so one action item can close many
findings. Status machine: Open → In progress / Risk accepted (with expiry) / Not affected
(backed by a VEX statement) → Resolved, with automatic reopen if the component reappears in a
later SBOM. Reconcile with the existing `TriageState` (OPEN/ACKNOWLEDGED/SNOOZED/RESOLVED/
FALSE_POSITIVE) rather than discarding it — decide during implementation whether ACKNOWLEDGED/
SNOOZED become sub-states of "In progress" or stay as-is alongside the new statuses. Risk
acceptance requires resolving the still-open approval-policy question first (see decisions
table).

**M1k — Role-based views.** One correlated data model, three views chosen by role:
  - **Leadership**: metrics and charts only (risk trend, findings by severity, MTTR, KEV
    exposure, SBOM-stage coverage per product) — no row-level drill-down by default.
  - **Security engineer**: today's Actionable Items experience (score per product/asset, ranked
    action items, triage) plus VEX authoring, risk acceptance, owner assignment/reassignment,
    and feed/policy tuning.
  - **Software engineer**: only action items for products/repos they own, each with a concrete
    fix; can mark in-progress, fix, or dispute with a VEX justification.

  Roles are assigned per tenant by tenant admins; a user can hold more than one role and switch
  views. Tenant admin (connectors, feeds, VEX precedence, role assignment) is a separate
  permission, not a view. Every view links down to the same finding detail page.

**M1l — Dependency graph preserved.** Keep the full dependency tree from each SBOM, not
flattened as today. Each finding records whether its component is direct or transitive, plus
the path from the product root — feeds both M1i's scoring input and the M1d lineage graph.

**M1 feeds wiring.** No new feed engineering — reuse all 8 existing feeds as-is. Add: a
per-tenant enable/disable toggle per feed; rescore-going-forward semantics (existing findings
keep their score when a feed is toggled, new/re-evaluated findings use current config, each
finding stores a snapshot of the feed configuration that scored it); toggle changes go into the
M1j-era audit trail once the audit log exists (Tenancy hardening) — track them in `TriageEvent`-
style history in the meantime if useful sooner; feed health (last successful sync, record
count, stale-feed surfacing to admins) and licensing/redistribution-terms metadata per feed.

**M1 acceptance criteria** (from the design doc):
- [ ] A fixture set of SBOMs, one per stage for one sample product, ingests with zero errors and
      produces one deduplicated component inventory.
- [ ] A deliberately injected Build-only component produces a Source-vs-Build drift finding.
- [ ] A KEV-listed vulnerability in a deployed component outranks the same CVE present only in
      source.
- [ ] A tenant `not_affected` VEX statement moves the finding to Not affected with the
      justification shown.
- [ ] Disabling a feed does not change existing scores; a newly ingested SBOM is scored without
      it.
- [ ] A software engineer mapped to one product sees only that product's action items.
- [ ] Malformed and oversized documents are rejected safely with a clear error.

### M2 — GitHub
*Goal: upgrade the existing GitHub connector from "pull one SBOM export" to the design doc's
full integration — this is an upgrade to Phase 6b's shipped connector, not a build from
scratch, so it's cheaper than its position in the dependency order suggests.*

- Swap the instance-wide `SECY_GITHUB_TOKEN` PAT for a **GitHub App**, org-scoped,
  least-privilege permissions.
- Keep the existing dependency-graph SBOM pull (already shipped); add **Dependabot alerts** and
  **code scanning alerts** ingestion.
- **Ownership inference** (M1b's stub): parse CODEOWNERS files and GitHub team repo permissions
  into ownership links with `source = INFERRED`.
- **Product tagging** (M1a's stub): repo tags/topics feed the configured product tag key.
- **Ticket sync**: two-way sync with GitHub Issues for action items — Secy creates an issue in
  the owning repo, status changes flow both ways. Secy wins on finding data; the issue wins on
  assignee and workflow state. (M1: no external sync — action items live in Secy only, per the
  design doc; this lands the "next phase" the doc describes.)

### M3 — Cloud & runtime
*Goal: upgrade the existing AWS/Azure connectors' auth model and add the two integrations the
old roadmap never built (Kubernetes, container registries).*

- **AWS**: replace static instance-wide credentials with a cross-account IAM role + external ID,
  `SecurityAudit` or `ReadOnlyAccess` — keep the existing EC2/ECR/Lambda + Inspector2 pull.
- **Azure**: replace the static service-principal secret with workload identity federation (or
  a scoped service principal as a fallback) with Reader role — keep the existing VM/ACR +
  Defender for Cloud pull.
- **Kubernetes** (new): read-only service account against EKS/AKS/self-managed clusters — running
  workloads, image digests, namespaces, labels.
- **Container registries** (new): registry-native read credentials for ECR/ACR/GHCR — image
  digests, tags, attached SBOMs and attestations.
- **Linking**: image digests connect registries → K8s workloads → cloud assets, and connect
  builds to their build SBOMs — feeds the M1d lineage graph.
- **Ownership inference**: cloud resource owner tags, same pattern as M2's CODEOWNERS inference.
- **Sync model**: scheduled polling per connector, same as today; event sources (EventBridge,
  Event Grid, K8s watch) are explicitly out of v1 scope (see Non-goals).

### M4 — Provenance
*Goal: verify what M1-M3 ingested was actually built the way it claims to have been.*

- Ingest and verify **SLSA provenance**, **in-toto attestations**, and **Sigstore/cosign
  signatures**.
- Unsigned or unverifiable artifacts become findings (feeding M1j's Finding model).
- The design doc notes this could fold into M3 if preferred once M3 is scoped in detail — leave
  that call for then, not now.

### Tenancy hardening
*Goal: the "Security of Secy itself" section of the design doc — Secy holds a map of every
tenant's exploitable weaknesses plus read credentials to their code and cloud, so it has to be
built as a high-value target, not bolted on at the end.*

Start once M1's functional core is demoable; finish before any real second tenant onboards
(i.e. before this stops being a solo-dogfooding instance).

- **Row-level security**: enforce Postgres RLS on every `tenant_id`-bearing table from M0.
  Cross-tenant queries become impossible by construction, not by convention.
- **Per-tenant credential storage**: connector secrets (GitHub App keys, AWS role ARNs, Azure
  federation config) encrypted with per-tenant keys through a KMS abstraction — cloud KMS for
  SaaS, pluggable for self-hosted. Replaces the M2/M3-era env-var-token pattern once this lands.
  Secrets are never logged or returned by the API.
- **AuthN/AuthZ**: SSO (OIDC/SAML), scoped API tokens, role-based access matching M1k's three
  views plus tenant admin.
- **Audit log**: all admin actions — connector changes, feed toggles, VEX precedence changes,
  risk acceptances, role changes.

### Packaging & self-hosted edition
*Goal: the design doc's "no hard dependency on any one cloud's managed services" + "self-hosted
ships as containers with a Helm chart."*

Carries the old roadmap's Phase 9 forward — 9a (Docker images, top-level compose, CI skeleton)
already shipped 2026-09-10 (commit `6cdaa5e`), unverified against a real `docker build`/
`docker compose up` (no Docker in the devcontainer).

- **Helm chart** for self-hosted multi-tenant-capable deployment.
- **Object storage**: raw SBOM, VEX, and attestation documents stored behind an S3-compatible
  interface (MinIO for self-host, S3/equivalent for SaaS) rather than only in Postgres.
- Every external dependency swappable through configuration — this is the concrete reason
  Apache AGE (M1d) won over Amazon Neptune.
- First-run UX, CI, ops (health/readiness, structured logging, metrics), and a security pass
  (dependency scanning, rate limiting, CORS, secret hygiene) carry forward unchanged from the
  old roadmap's Phase 9 scope — see that phase's write-up in git history for the original
  detail if needed.

---

## Suggested order & interleaving

```
M0  ─────────────▶ (unblocks everything; do first)
M1a ──▶ M1b ──▶ M1c        (product/ownership/identity — cheap, mostly additive)
M1d ──▶ M1e                (graph DB + lifecycle diffing — needs M1c's identity model)
M1f ──▶ M1g ──▶ M1h ──▶ M1i (VEX/CBOM/quality feed the scoring engine)
M1j ──▶ M1k ──▶ M1l        (Finding/Action-item model + role views need scoring first)
M2  ──▶                    (upgrade of an existing connector — cheap)
M3  ──▶                    (mostly parallel with M2; K8s/registry are new builds)
Tenancy hardening ──▶      (start once M1 is demoable; finish before a 2nd tenant)
M4  ──▶                    (after M3 is scoped; may fold into M3)
Packaging/Helm ──▶         (start early on compose/CI as before, Helm chart later)
```

M2 and M3's connector-auth upgrades are cheaper than their position in this diagram implies —
they're extending Phase 6b's shipped code, not building from zero. Kubernetes and registry
connectors inside M3 are the genuinely new work there.

---

## Definition of done — v1

Supersedes the old roadmap's single-tenant DoD checklist.

**M1**
- [ ] A fixture set of SBOMs, one per stage for one sample product, ingests with zero errors and
      produces one deduplicated component inventory.
- [ ] A deliberately injected Build-only component produces a Source-vs-Build drift finding.
- [ ] A KEV-listed vulnerability in a deployed component outranks the same CVE present only in
      source.
- [ ] A tenant `not_affected` VEX statement moves the finding to Not affected with the
      justification shown.
- [ ] Disabling a feed does not change existing scores; a newly ingested SBOM is scored without
      it.
- [ ] A software engineer mapped to one product sees only that product's action items.
- [ ] Malformed and oversized documents are rejected safely with a clear error.
- [ ] All three role views render off the same underlying finding data.

**M2 / M3**
- [ ] GitHub sync runs under a GitHub App, not a static PAT; ownership + product tags populate
      from CODEOWNERS/teams/repo topics without manual mapping.
- [ ] AWS/Azure sync runs under cross-account IAM / workload identity, not static keys.
- [ ] A Kubernetes cluster and a container registry each sync into the asset inventory with
      image-digest linking connecting them to their build SBOM.

**Tenancy hardening**
- [ ] A cross-tenant query is impossible at the database level (RLS), demonstrated by a test.
- [ ] Connector credentials are encrypted at rest per tenant and never returned by the API.
- [ ] SSO login works end to end; every API call carries a scoped token matching the caller's
      role(s).
- [ ] Every admin action (connector change, feed toggle, VEX precedence change, risk acceptance,
      role change) appears in the audit log.

**Packaging**
- [ ] `docker compose up` from a clean checkout yields a working single-tenant Secy.
- [ ] The Helm chart deploys a working Secy on a clean cluster.
- [ ] CI green: both builds, both test suites, lint, typecheck, Liquibase validate.

---

## Non-goals for v1

Replaces the old roadmap's "explicitly not in MVP" list.

- **Generating** SBOMs, VEX, or attestations — Secy ingests only; a generator suite is future
  expansion.
- GitLab, Azure DevOps, and Bitbucket integrations.
- GCP.
- Jira, Azure Boards, and ServiceNow ticket sync (GitHub Issues only, M2).
- Event-driven inventory sync (EventBridge, Event Grid, K8s watch) — scheduled polling only.
- Write access to customer cloud environments, or automated remediation (auto-PRs).
- Commercial threat-intel feeds (Mandiant, Recorded Future, Flashpoint) — closed feeds don't fit
  the OSS core; would belong in an open-core commercial layer if ever added.

---

## Future expansion (post-v1)

- A suite of SBOM generators (source, build, binary, runtime) feeding the same ingestion layer.
- Tenant-configurable scoring weights (M1i centralizes them now so this is additive later).
- Policy engine with pass/fail gates (e.g. no KEV in prod, minimum SBOM quality score).
- Splitting modules into services in the best-fit language, per the modular-monolith module
  boundaries defined below.
- IOC-vs-telemetry validation (the old roadmap's vNext direction: CVE→IOC enrichment + hunt-pack
  export, optional SIEM/EDR connectors, host-agent local checks) — still not in scope; needs
  telemetry Secy isn't a source of.
- Distro security trackers (Debian/Ubuntu/RHEL CSAF-VEX/SUSE/Alpine) for `will-not-fix`/
  `deferred` lifecycle states OSV doesn't carry — still valuable, still deferred.

---

## Architecture & tech stack

- **Frontend**: React (existing) — `ui/`.
- **Backend**: Java Spring Boot (existing) as a **modular monolith** — `api/`. Expected module
  boundaries: ingestion (parsers per format), identity resolution, feeds, correlation and
  diffing, scoring, findings and action items, connectors, tenancy and auth. Modules talk only
  through defined interfaces, not shared tables or internals, so any one can become a service
  later without a rewrite.
- **Data**: PostgreSQL as the system of record (unchanged); **Apache AGE** graph extension for
  lineage/blast-radius traversal (M1d), derived from and rebuildable from Postgres.
- **Raw documents**: original SBOM/VEX/attestation files stored in S3-compatible object storage
  (Packaging & self-hosted edition), not just parsed into Postgres.
- **Background work**: ingestion, feed sync, connector polling, and rescoring run as queued jobs
  (existing `job/` module, unchanged pattern) — retried and observable, never inline in a
  request.
- **Deployment**: multi-tenant SaaS by default + self-hosted edition via Helm, no hard
  dependency on any one cloud's managed services.

---

## Security of Secy itself

Secy holds a map of every tenant's exploitable weaknesses plus read credentials to their code
and cloud — it's a high-value target and has to be built like one.

- **Tenant isolation**: every row and graph node carries a tenant ID (M0); Postgres RLS enforced
  (Tenancy hardening). Cross-tenant queries impossible by construction.
- **Credentials**: connector secrets encrypted with per-tenant keys through a KMS abstraction;
  never logged or returned by the API (Tenancy hardening).
- **Least privilege**: connectors request read-only scopes only; Secy never needs write access
  to customer clouds; GitHub write is limited to Issues (M2).
- **AuthN/AuthZ**: SSO (OIDC/SAML) + role-based access matching M1k's three views plus tenant
  admin; scoped API tokens (Tenancy hardening).
- **Audit log**: all admin actions (Tenancy hardening).
- **Untrusted input**: every uploaded SBOM/VEX/attestation treated as hostile — size limits,
  safe XML parsing (no XXE), bounded dependency-tree recursion. Applies from M1 onward, not
  deferred to hardening.
- **Supply chain**: Secy's own builds produce SBOMs and signed provenance, and Secy ingests them
  about itself (once M4 exists).

---

## Open questions

Carried forward from the design doc rather than silently decided:

- ~~**Product tag key default**: recommending `secy:product`, but this is not locked — confirm
  before M1a ships, since it's cheap to change now and expensive once tenants have tagged
  resources against it.~~ **Resolved**: `secy:product` locked in as the default, configurable
  per tenant via `GET`/`PUT /settings/product-tagging` — see M1a's status note.
- **Risk acceptance approval**: security-engineer approval vs. owner self-accept — genuinely
  open, decide before M1j builds the risk-acceptance flow.
- **Sample fixtures**: recommending synthetic fixtures extending the existing correlation
  golden-set pattern (`api/src/test/resources/correlation/`) — real anonymized SBOMs are the
  alternative if synthetic ones prove too easy to over-fit to.

---

## Cross-cutting / carried-over

- `feat/phase-1-actionable-core` is the base branch for M0 onward — it is **not** merged to
  `master` yet and holds all of the "current state" substrate described above. A future session
  should not assume this work has landed on `master`.
- **vitest OOMs in the devcontainer** (V8 heap / tinypool IPC). Full suite passes on a real
  machine. Add a CI job as the source of truth; consider raising devcontainer memory. Don't
  chase the local flaky exit code.
- **NVD API key rotation** — still owed by the user at nvd.nist.gov (scrubbing hid it, rotation
  kills it). The old `jdesive/secy-api` GitHub repo history still contains it.
- **Delete stale repos** — old `jdesive/secy-*` repos (user task) before anything goes public.
- **Backend integration tests** need a DB; devcontainer has no Docker. Decide: Testcontainers in
  CI only, or keep H2 for tests and accept the fidelity gap.
- Keep `CLAUDE.md` and the memory notes in sync as milestones land.
