# Secy — Roadmap to MVP

> Working document. Updated as milestones land. Pairs with `CLAUDE.md` (how the repo
> is laid out) and the session memory notes. Last revised 2026-09-05.

## What the MVP is

**A self-hostable OSS security-posture platform that turns SBOMs, infra scans and
compliance reports into a short, ranked list of vulnerabilities that actually matter.**

Someone clones the repo, runs `docker compose up`, registers the first (admin) user,
points Secy at their assets, and gets an **Actionable Items** screen driven by the
funnel: *KEV-listed **OR** EPSS > 0.1*.

### Decisions locked in (2026-09-05)

| Question | Decision |
|---|---|
| Delivery model | **Self-host OSS first.** One-command Docker Compose, single tenant, local JWT. Helm chart + hosted multi-tenant SaaS are **post-MVP**. |
| Actionable core | **Full build** — KEV/EPSS enrichment wired into scanning, `/actionable` endpoint, first-class Actionable Items view as the primary screen. |
| Correlation quality | **Solid** — OSV-primary for open-source packages (PURL-native, ships the fix version), NVD CPE range matching (`versionStart/EndIncluding/Excluding`) as fallback and for non-package assets. Not the current `split(":")[5]` hack. |
| Feeds (MVP) | NVD, KEV, EPSS, **OSV.dev**, **CISA Vulnrichment / CVE List v5**. OSV supplies package↔CVE matches + per-ecosystem fix versions; Vulnrichment/CVE-5.1 supplies SSVC decision points, current CVSS/CWE/CPE (NVD has a backlog) and `REJECTED`/`DISPUTED` status. KEV = exploitation, EPSS = probability — neither is replaceable. NVD stays canonical for non-package (OS/firmware/proprietary) CPE data. Further feeds tracked in **Feed backlog** below. |
| Fix version | Every actionable item carries a fix state: `FIXED` (+ version(s)), `NO_FIX` (none published yet), `UNKNOWN`. Shown as a badge/column; opt-in "only with a fix" filter, remembered per-user. Sources in precedence order: OSV (packages) → scanner `FixedVersion` (assets) → NVD CPE-range-derived (approximate, flagged). |
| Exploit signal | Beyond KEV membership, each alert carries `exploitMaturity` (`NONE` / `POC` / `WEAPONIZED` / `IN_THE_WILD`) derived from a merged public-exploit index (Nuclei templates + Metasploit modules + PoC-in-GitHub) and KEV. Plus `kevDueDate`, `knownRansomwareUse`, `epssPercentile` surfaced directly. |
| SBOM formats | **CycloneDX + SPDX**, both normalized to one internal component model. |
| Infra inventory | **Trivy / Grype JSON ingest** for MVP. **Cloud/agent discovery** is a stretch item (Phase 9) and may land as a fast-follow. |
| Compliance | Docker / CIS: finish the backend, build the Compliance view. |
| Triage | Alert state workflow (ack / snooze / resolve / false-positive) with history. |
| Ingestion | Scheduled auto-refresh of NVD/KEV/EPSS on a cron; NVD incremental pulls. |
| Notifications | Email + generic webhook on new actionable items. |
| Reporting | CSV + PDF export of the actionable list / posture summary. |
| Capacity | Solo + Claude Code sessions. Milestone-paced, no hard date. |

### Explicitly NOT in the MVP

Multi-tenancy, billing, self-serve sign-up, OIDC/SSO, fine-grained RBAC, audit log
(these are the planned open-core commercial add-ons), Helm chart, hosted SaaS,
agent-based fleet discovery (unless Phase 9 finishes early), SPDX RDF/XML (JSON only),
non-Docker CIS benchmarks.

---

## Current state (baseline)

**Backend (`api/`)** — Spring Boot 3.3, Java 17, PostgreSQL, Liquibase, OpenAPI.
- Feed ingestion NVD / KEV / EPSS via a DB-polled job queue (`job/`, `POST /{feed}/ingest` → 202 + Job, `GET /jobs`).
- JWT auth, single tenant, first registered user → ADMIN (`auth/`, `security/`).
- SBOM upload → async event → `VulnerabilityScanner` → `AlertService.generateAlerts(SBOM)` → `VulnerabilityAlert` rows.
- CIS/Docker: `CISController` ingests a report and has a `GET /cis/docker/scan/{id}` alert generator. No pagination, not job-queued, no list endpoints.
- `GET /stats/dashboard` roll-up.

**Frontend (`ui/`)** — React 18, Vite 6, TanStack Router/Query/Table, Tailwind + shadcn.
- Views at parity: Dashboard, KEV / EPSS / CVE database browsers, Product Catalog + SBOM upload/history/vuln-detail modals.
- `Infrastructure` and `Compliance` are `PlaceholderPage` routes.
- Auth shell (`ui/src/auth/`), code-split routes, ~160 KB gz initial bundle.

**Known weak points the roadmap must fix**
1. `AlertService.generateAlerts(SBOM)` never consults KEV or EPSS — the funnel isn't applied anywhere. There is no "actionable" concept in the data model, only raw alerts.
2. `CPEMatch` stores `criteria` only — no version-range columns. Version check is `criteria.split(":")[5]` + a loose numeric compare. High false-positive/negative rate.
3. No PURL ecosystem awareness — one CPE name-pattern query for every component regardless of npm/maven/pypi/golang.
4. No fix-version data anywhere — an alert can't say whether a patch exists.
5. Only 3 feeds; no OSV (package matching leans entirely on NVD CPE guessing), no exploit-availability signal, and NVD's analysis backlog leaves recent CVEs with no CVSS/CWE.
6. KEV is ingested but `dueDate` / `knownRansomwareCampaignUse` are unused; EPSS percentile isn't stored.
7. CycloneDX model is bespoke; no shared normalized component model; no SPDX.
8. No app container images, no top-level compose, no CI.
9. Feeds only refresh on a manual button press; NVD pull is a full re-pull.

---

## Milestones

Each phase is independently shippable and leaves `master` green
(`cd api && ./gradlew build`; `cd ui && npm run build && npm test`).

### Phase 1 — The actionable core
*Goal: the funnel exists end to end and is the first thing you see.*

- **Data model**: enrichment join `VulnerabilityAlert → Vulnerability (CVE) → EPSS score + KEV membership`. Add a computed/persisted `actionable` flag + `actionableReason` (`KEV` / `EPSS_HIGH` / both) and denormalized `epssScore` / `epssPercentile` / `cvssScore` on the alert for sorting. Also add `fixState` (`FIXED` / `NO_FIX` / `UNKNOWN`), `fixedVersions` (text), `fixSource` (`OSV` / `SCANNER` / `CPE_RANGE`), `exploitMaturity` (`NONE` / `POC` / `WEAPONIZED` / `IN_THE_WILD`), `kevDueDate`, `knownRansomwareUse`. Liquibase changeset.
- **Exploit index feed**: one ingester that merges Nuclei templates (`projectdiscovery/nuclei-templates`, `cves.json`), Metasploit modules (`rapid7/metasploit-framework`, `db/modules_metadata_base.json`) and PoC-in-GitHub (`nomi-sec/PoC-in-GitHub`) into a `cve_exploit` table (CVE → highest maturity + source links). `POST /exploits/ingest` + scheduled refresh. `exploitMaturity` = max(KEV ⇒ `IN_THE_WILD`, Metasploit/Nuclei ⇒ `WEAPONIZED`, PoC-in-GitHub ⇒ `POC`, else `NONE`).
- **Threshold config**: `SECY_ACTIONABLE_EPSS_THRESHOLD` (default `0.1`), documented alongside the other env vars.
- **Scanning**: `AlertService` (and the Docker path) set `actionable` + reason at alert-generation time; a re-enrichment job re-evaluates existing alerts after each EPSS / KEV / exploit-index ingest. `fixState` is populated from scanner `FixedVersion` where present, else `UNKNOWN` (OSV/CPE-range population arrives in Phase 2).
- **API**: `GET /actionable` — paged, filter by `productId` / `assetId` / `reason` / `minCvss` / `state` / `fixState` / `minExploitMaturity`, sort by EPSS desc default. `GET /actionable/{id}` detail (CVE, affected components/assets, fix version(s), exploit links, KEV due date, feed evidence).
- **Dashboard**: `DashboardStats` gains real actionable counts (open, by reason, by severity, with-fix vs. without, by exploit maturity, past-KEV-due-date, trend vs. 7d).
- **UI**: new **Actionable Items** view becomes `/` (index). Table with severity, EPSS (score + percentile), KEV badge, **Exploit badge** (PoC / Weaponized / In-the-wild), **Fix badge** (version / "none yet" / "unknown"), affected product/asset, age; row → detail drawer reusing `CveDetailPanel`. Opt-in toggles for "only with a fix" and "only with a known exploit", persisted per-user (localStorage). Dashboard stays at `/dashboard`.
- **Tests**: service-level funnel tests; `/actionable` filter/sort contract tests (incl. `fixState`, `minExploitMaturity`); exploit-index merge tests; a UI view test.

### Phase 2 — Correlation engine rework (OSV-primary)
*Goal: the actionable list is trustworthy, and it knows whether a fix exists.*

- **OSV feed** (feed #4): mirror OSV's per-ecosystem exports (`gs://osv-vulnerabilities/<ecosystem>/all.zip`) into Postgres via the job queue, same pattern as NVD/KEV/EPSS. New `osv_advisory` table: ecosystem, package, aliases (CVE/GHSA), affected `introduced`/`fixed`/`last_affected` ranges, severity/CVSS vector, references. `POST /osv/ingest` + scheduled refresh. Store a per-ecosystem high-water mark.
- **CVE List v5 + Vulnrichment feed** (feed #5): ingest CVE JSON 5.1 records (bulk from `CVEProject/cvelistV5`, hourly deltas) including the CISA-ADP **Vulnrichment** container. Populate on `Vulnerability`: `cveStatus` (`PUBLISHED` / `REJECTED` / `DISPUTED`), best-available CVSS + `cvssSource` (NVD → CNA → ADP precedence), CWE, and SSVC decision points (`ssvcExploitation`, `ssvcAutomatable`, `ssvcTechnicalImpact`). `POST /cve/ingest` + scheduled refresh. `REJECTED` / `DISPUTED` CVEs are excluded from the actionable funnel (still visible in the CVE browser, flagged).
- **Primary correlation path** — for every `NormalizedComponent` with a PURL: look up `osv_advisory` by ecosystem + package, evaluate the component version against each affected range using the ecosystem's version scheme. A hit → alert, resolved to a CVE via OSV aliases, with `fixState`/`fixedVersions` taken straight from the OSV `fixed` events (`fixSource = OSV`).
- **Fallback / non-package path** — NVD CPE matching for components OSV doesn't cover and for infra/OS assets:
  - **Schema**: extend `CPEMatch` with `versionStartIncluding/Excluding`, `versionEndIncluding/Excluding`; populate from the NVD `configurations[].nodes[].cpeMatch[]` payload during ingest (`NVDService`). Liquibase + a re-ingest note.
  - **Matching**: replace `split(":")[5]` with proper CPE 2.3 parsing (vendor, product, version, update) and range evaluation.
  - **Fix guess**: derive an approximate fix version from the vulnerable range's `versionEndExcluding` when present; `fixSource = CPE_RANGE`, flagged approximate in the UI.
- **PURL → CPE bridge** (fallback only): map PURL `type` → vendor/product heuristics (`maven` groupId/artifactId, `npm`/`pypi`/`golang`/`nuget`/`gem` ecosystem name). Unknown type → broad name-pattern fallback, lowest confidence.
- **Version comparison**: pluggable `VersionScheme` per ecosystem (SemVer, PEP 440, Maven, Go, generic); one shared implementation used by both the OSV and CPE paths. Replaces the single `util/Version` class.
- **Alert lifecycle**: on re-scan, alerts whose match no longer holds are marked `RESOLVED (auto)` rather than deleted; new matches added; no duplicates. Re-enrichment refreshes `fixState` when OSV/NVD data changes.
- **Confidence**: each alert carries `matchConfidence` (`EXACT` / `RANGE` / `HEURISTIC`) and `fixSource`; both surfaced in the UI.
- **Golden set**: `api/src/test/resources/correlation/` — 4–6 real SBOMs with hand-verified expected CVEs *and* expected fix versions; a test asserts precision/recall stays above a documented bar.

### Phase 3 — SBOM breadth (SPDX) + ingest hardening
- Introduce `model/component/NormalizedComponent` (name, version, purl, ecosystem, licenses, scope).
- Refactor CycloneDX parsing → `NormalizedComponent`; scan pipeline consumes only the normalized model.
- Add SPDX (JSON, 2.2 + 2.3) parser → `NormalizedComponent`. Detect format on upload; reject unknown with a clear 400.
- SBOM upload goes through the job queue (consistent with feeds) with progress + failure surfacing in the UI.
- Component de-dup within a product across SBOM versions so history diffs are meaningful.

### Phase 4 — Infrastructure / asset inventory
- **Domain**: `Asset` (type: `CONTAINER_IMAGE` / `HOST` / `SERVICE`), optional link to `Product`, holds `NormalizedComponent`s and/or declared CPEs, `lastScannedAt`.
- **Ingest**: `POST /assets/scan/trivy` and `.../grype` — parse scanner JSON (image + filesystem), create/update the asset, import its components, and capture each finding's `FixedVersion` → alert `fixState`/`fixedVersions` (`fixSource = SCANNER`).
- **Correlation**: scanner-reported CVEs become alerts immediately; Secy also re-correlates (OSV + KEV/EPSS) so scanner output flows through the same funnel and picks up an OSV fix version when the scanner didn't supply one.
- **API**: `GET /assets` paged + filter, `GET /assets/{id}` with its actionable items, `DELETE /assets/{id}`.
- **UI**: build the **Infrastructure** view — asset list, per-asset drilldown, "scan output" upload modal (mirrors SBOM upload). Actionable Items view gains an asset filter.

### Phase 5 — Compliance (Docker / CIS)
- Job-queue the report scan; replace `GET /cis/docker/scan/{id}` with `POST /compliance/reports/{id}/scan`.
- **API**: `GET /compliance/reports` paged, `GET /compliance/reports/{id}` (pass/fail summary, misconfig + vuln alerts paged), remediation text included.
- Docker vuln alerts feed the same enrichment/funnel as SBOM alerts where a CVE is present.
- **UI**: build the **Compliance** view — report list, per-report control breakdown (pass/fail/skip), misconfiguration list with remediation, linked vuln actionable items.

### Phase 6 — Triage workflow
- **State machine** on every alert: `OPEN → ACKNOWLEDGED → SNOOZED(until) → RESOLVED | FALSE_POSITIVE`, plus `assignee` and free-text `notes` / comment thread with an append-only history table.
- **API**: `PATCH /actionable/{id}` (state, assignee), `POST /actionable/{id}/comments`, bulk `PATCH /actionable` for multi-select.
- Default Actionable Items query hides `SNOOZED` (until expiry) and `RESOLVED` / `FALSE_POSITIVE`; a state filter shows them.
- **UI**: row multi-select + bulk actions; detail drawer shows state, assignee, history, comment box.

### Phase 7 — Scheduled ingestion, notifications, reporting
- **Scheduler**: cron-triggered feed refresh for all feeds — NVD, KEV, EPSS, OSV, CVE-5.1/Vulnrichment, exploit index (`SECY_INGEST_SCHEDULE_*`, default daily) via the job queue; disabled by default with a clear opt-in.
- **NVD incremental**: use `lastModStartDate` / `lastModEndDate` windows instead of full re-pull; store the high-water mark.
- **Notifications**: `notification/` module — on a new actionable item for a subscribed product/asset, deliver via SMTP email (`SECY_SMTP_*`) and/or a generic JSON webhook (`POST` with an HMAC signature header). Per-user + per-product subscriptions, managed in Settings.
- **Reporting**: server-generated **CSV** and **PDF** (posture summary + actionable list) scoped to a product / asset / whole org. `GET /reports/actionable.{csv,pdf}`; UI download button on the Actionable and Product views.

### Phase 8 — Packaging & release (the OSS deliverable)
- **Images**: multi-stage `api/Dockerfile` (slim JRE 17) and `ui/Dockerfile` (build → nginx serving static + proxying `/api`).
- **Top-level `docker-compose.yml`**: `postgres` + `api` + `ui`, single `docker compose up`, `.env.example` with every knob, healthchecks, named volume.
- **First-run UX**: registration open until the first admin exists, then auto-locked unless `SECY_AUTH_REGISTRATION_ENABLED=true`; documented.
- **CI** (GitHub Actions): build + test both halves on PR; build & push tagged images on release; Liquibase validate; `npm run lint` + `typecheck`.
- **Ops**: actuator health/readiness wired into compose; structured JSON logging; Prometheus metrics endpoint; sensible connection-pool + JVM defaults.
- **Security pass**: dependency scan (OWASP Dependency-Check / `npm audit` in CI), rate-limit `/auth/**`, review CORS, confirm no secret in a tracked file, JWT secret must be set in non-dev.
- **Docs**: `docs/` — install & upgrade guide, full config reference, architecture overview, "how the funnel works", `CONTRIBUTING.md`, `SECURITY.md`.
- **README**: update screenshots + quickstart to the compose flow.

### Phase 9 — Stretch: cloud & agent discovery
*May ship as a fast-follow after the MVP tag.*
- Lightweight inventory sync from a cloud provider API (start with one: AWS) and/or a minimal agent that reports installed packages.
- Populates `Asset`s and their components; everything downstream already works.

---

## Suggested order & interleaving

```
Phase 1  ─────────────▶ (unblocks everything; do first)
Phase 2  ──────▶        (right after 1; correctness gate)
Phase 3  ──▶            (can overlap tail of 2)
Phase 4  ──▶            (needs 3's normalized model)
Phase 5  ──▶            (independent of 3/4; slot when convenient)
Phase 6  ──▶            (needs 1; independent of 2–5)
Phase 7  ──▶            (needs 1; email/report need 4–5 for full value)
Phase 8  ─────────────▶ (start compose/CI early, finish last)
Phase 9  ──▶            (stretch)
```

Recommended path: **1 → 2 → 8a (compose + CI skeleton) → 3 → 4 → 5 → 6 → 7 → 8b (polish + docs) → tag MVP → 9**.

The **feed ingesters** (OSV and CVE-5.1/Vulnrichment in Phase 2, the exploit index in Phase 1)
have no dependency on the alert model and can be built first or in parallel — only the logic that
*consumes* them (OSV-primary correlation, `exploitMaturity` derivation) needs Phase 1's schema.

---

## Definition of done — MVP

- [ ] `docker compose up` from a clean checkout yields a working Secy (UI + API + DB).
- [ ] First user registers as admin; subsequent registration locked by default.
- [ ] All six feeds (NVD / KEV / EPSS / OSV / CVE-5.1+Vulnrichment / exploit index) ingest (manually and on schedule) and refresh incrementally.
- [ ] Upload a CycloneDX **and** an SPDX SBOM → components correlated (OSV-primary) → actionable items appear with fix versions where known.
- [ ] Ingest a Trivy/Grype scan → asset appears with its actionable items and scanner-reported fix versions.
- [ ] Ingest a Docker CIS report → Compliance view shows controls + alerts.
- [ ] Actionable Items view: filter (incl. "only with a fix", "only with a known exploit"), sort by EPSS, Fix + Exploit badges on every row, open a detail drawer, ack/snooze/resolve, bulk-action.
- [ ] `REJECTED` / `DISPUTED` CVEs are kept out of the actionable funnel.
- [ ] New actionable item on a watched product fires an email + webhook.
- [ ] Export the actionable list as CSV and PDF.
- [ ] Correlation golden-set test passes at the documented precision/recall bar.
- [ ] CI green: both builds, both test suites, lint, typecheck, Liquibase validate.
- [ ] `docs/` install + config + architecture pages complete; README quickstart matches reality.

---

## Feed backlog (post-MVP)

Additional intelligence sources, roughly in priority order. Each improves one of the
alert-decision dimensions: *is it exploited*, *how bad*, *can I fix it*, *does it apply to me*.

| Feed | Decision dimension | What it adds | Effort | Suggested slot |
|---|---|---|---|---|
| **Distro security trackers** — Debian, Ubuntu (USN), **Red Hat CSAF/VEX**, SUSE, Alpine secdb | Can I fix it? | Distro-specific fixed package versions **and** lifecycle states OSV lacks: `will-not-fix`, `deferred`, `out-of-support`, `affected-no-fix-planned`. Essential to de-noise container base images. | Medium (one ingester per distro; OVAL/CSAF/JSON) | Alongside Phase 4 (asset/container correlation) |
| **VEX ingestion + suppression** — OpenVEX / CSAF-VEX / CycloneDX-VEX | Does it apply to me? | Vendor/internal "not affected" statements → auto-suppress or downgrade alerts. Biggest noise reducer. Pairs with the triage model. | Medium (parser + suppression rules + provenance) | Extends Phase 6 |
| **GreyNoise** (community API) | Is it exploited *now*? | Tags CVEs with observed internet-wide mass-scanning / exploitation attempts — leads KEV/EPSS on fresh activity. | Low (API, rate-limited, needs key) | Enrichment polish |
| **endoflife.date** | How bad / can I fix it? | Runtime/component EOL dates — past EOL ⇒ no fix will ever come ⇒ raise priority instead of leaving it `UNKNOWN`. | Low (one JSON API) | Enrichment polish |
| **VulnCheck KEV** (community) | Is it exploited? | Superset of CISA KEV — exploited CVEs CISA hasn't catalogued, plus initial-access / ransomware tags and exploit refs. | Low (API + key) | Enrichment polish |
| **GitHub Security Advisories** (GraphQL, direct) | Can I fix it? | Beyond what OSV mirrors: withdrawn/updated status, CVSS v4, richer affected ranges. | Low–medium | Only if OSV coverage proves thin |
| **CWE / CAPEC taxonomy** (MITRE) | How bad / explain | Human-readable weakness + attack-pattern context; lets alerts be grouped by root cause. | Low (static import) | Reporting / UX polish |
| **Reachability analysis** (not a feed — an engine) | Does it apply to me? | Static call-graph analysis to confirm the vulnerable symbol is actually invoked. Large; likely a separate initiative. | High | Long-term |

**Commercial threat-intel** (Mandiant, Recorded Future, Flashpoint, etc.) is deliberately out
of scope — closed feeds don't fit an OSS core, and would belong in the open-core commercial layer if ever.

---

## Cross-cutting / carried-over

- **vitest OOMs in the devcontainer** (V8 heap / tinypool IPC). Full suite passes on a real machine. Add a CI job as the source of truth; consider raising devcontainer memory. Don't chase the local flaky exit code.
- **NVD API key rotation** — still owed by the user at nvd.nist.gov (scrubbing hid it, rotation kills it). Old `jdesive/secy-api` GitHub repo history still contains it.
- **Delete stale repos** — old `jdesive/secy-*` repos (user task) before anything goes public.
- **Backend integration tests** need a DB; devcontainer has no Docker. Decide: Testcontainers in CI only, or keep H2 for tests and accept the fidelity gap.
- Keep `CLAUDE.md` and the memory notes in sync as phases land.
