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
| Products | Tag-driven, tag key configurable per tenant (default `secy:product`, open question in the design doc — this is the recommended default, not yet locked). Untagged assets land in "Unassigned". Manual product assignment at upload time stays available until connectors exist. |
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

**M1b — Ownership model.** Manual mapping only in this sub-phase — inference needs M2/M3's
connectors (CODEOWNERS, GitHub team permissions, cloud resource tags). Each ownership link
records its source (`INFERRED` / `MANUAL`) even though only `MANUAL` is populated yet, so M2/M3
don't need a schema change to add inference.

**M1c — Canonical component identity.** Extend the existing `NormalizedComponent`/`identityKey`
(PURL-primary, built in the old roadmap's Phase 3) with CPE, SWID tag, and content hash as
secondary identifiers. When identifiers conflict across sources, flag the link low-confidence
instead of guessing a merge. Keep per-instance provenance (which SBOM, which stage, which
ingestion) — already partially present, formalize it as a first-class field.

**M1d — Lineage graph (Apache AGE).** Stand up Apache AGE as a Postgres extension (no new
service). Write lineage edges Product → Repo → Build → Image/Artifact → Workload/Cloud Asset,
and Build → Component (PURL) → Vulnerability → Finding → Action item, mirroring the design
doc's `flowchart LR`. Graph writes are derived from Postgres and must be rebuildable from it —
Postgres stays the system of record, the graph is a queryable index over it, not a second
source of truth.

**M1e — SBOM lifecycle stages + diffing.** Every SBOM is tagged with its stage (Source / Build /
Analyzed / Deployed) at ingestion, by upload metadata or API field. A diff engine runs
automatically whenever a new SBOM for a stage arrives and a comparable SBOM exists for the
adjacent stage:
  - Source vs Build mismatch → possible dependency confusion / build injection finding.
  - Build vs Deployed mismatch → runtime drift / unauthorized change finding.
  - Build vs Analyzed mismatch → incomplete SBOM / tampering finding.

**M1f — VEX ingestion.** CycloneDX VEX (embedded or standalone), OpenVEX, and CSAF VEX parsers
into a `VexStatement` model: status (`not_affected` with justification, `affected`, `fixed`,
`under_investigation`), precedence resolved per the tenant's configured rule (default: tenant
overrides vendor, conflicts flagged for review). Every finding shows which statements applied
and which one won.

**M1g — CBOM ingestion.** CycloneDX 1.6 cryptographic-asset ingestion: algorithms, keys,
certificates, protocols. Quantum-vulnerable algorithms (RSA, ECC) become their own finding
category. Confirm the current CycloneDX parser's version ceiling during implementation — the
design doc requires 1.6 specifically for this.

**M1h — SBOM quality scoring.** Score each ingested SBOM against the NTIA minimum elements
(supplier, name, version, unique ID, dependency relationships, author, timestamp). A low score
becomes its own finding category, surfaced per product.

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

- **Product tag key default**: recommending `secy:product`, but this is not locked — confirm
  before M1a ships, since it's cheap to change now and expensive once tenants have tagged
  resources against it.
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
