/**
 * Shared API types for the Secy backend.
 *
 * Ported from the Angular services (`ui/src/app/services/*.service.ts`) that this
 * React app replaces. Interface names are kept identical (`KEV`, `EPSS`, `SBOM`, …)
 * so the contract is greppable against the old code and against the Spring
 * entities in `api/src/main/java/net/jdesive/secy/persistence/entity/`.
 *
 * Deviation from the Angular originals: fields the Angular services typed as
 * `Date` are typed as `string` here. `HttpClient` never actually produced `Date`
 * objects — JSON carries ISO-8601 strings — so the old typings were wrong at
 * runtime. Parse at the point of display.
 */

/* -------------------------------------------------------------------------- */
/* Paging                                                                     */
/* -------------------------------------------------------------------------- */

/** Spring Data `Pageable` metadata, as serialized inside a `Page`. */
export interface Pageable {
  pageNumber: number;
  pageSize: number;
  offset: number;
  paged: boolean;
  unpaged: boolean;
  sort: Sort;
}

export interface Sort {
  sorted: boolean;
  unsorted: boolean;
  empty: boolean;
}

/**
 * Spring Data `Page<T>` envelope returned by every paged endpoint
 * (`/api/kev`, `/api/epss`, `/api/nvd/search`). `number` is 0-indexed.
 */
export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
  numberOfElements: number;
  first: boolean;
  last: boolean;
  empty: boolean;
  pageable?: Pageable;
  sort?: Sort;
}

/** Query parameters shared by the paged list endpoints. */
export interface PageParams {
  page: number;
  size: number;
  search?: string;
}

/* -------------------------------------------------------------------------- */
/* Ingestion jobs — POST /api/{feed}/ingest, GET /api/jobs                    */
/* -------------------------------------------------------------------------- */

/**
 * The kind of background job. `NVD` / `EPSS` / `KEV` / `EXPLOIT` are singleton
 * feed pulls — at most one of each active at a time. `EXPLOIT` is the merged
 * public-exploit index (Nuclei + Metasploit + PoC-in-GitHub) that feeds each
 * alert's `exploitMaturity`. `SBOM_UPLOAD` is different: one job per uploaded
 * document, so many may be active at once (see `useUploadSbom`).
 */
export type JobType =
  | 'NVD'
  | 'EPSS'
  | 'KEV'
  | 'EXPLOIT'
  | 'OSV'
  | 'CVE_LIST'
  | 'SBOM_UPLOAD'
  | 'ASSET_SCAN'
  | 'COMPLIANCE_SCAN';

/**
 * Job lifecycle. `QUEUED -> RUNNING -> (SUCCEEDED | FAILED | CANCELLED)`; the
 * last three are terminal, which is what stops the poll in `useJob`. Use
 * `isTerminalJobStatus` from `@/lib/jobs` rather than comparing by hand.
 */
export type JobStatus = 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED';

/**
 * A background feed ingestion.
 *
 * `POST /api/{feed}/ingest` answers 202 with one of these instead of blocking
 * for the whole download; the client then polls `GET /api/jobs/{id}`. Listing
 * jobs (`GET /api/jobs`) returns them inside the usual `Page<T>` envelope.
 */
export interface Job {
  /** UUID. */
  id: string;
  type: JobType;
  status: JobStatus;
  /** ISO-8601 date-time string. */
  createdAt: string;
  /** Null while the job is still queued. */
  startedAt?: string | null;
  /** Null until the job reaches a terminal status. */
  finishedAt?: string | null;
  /** Records written so far — a running count while `RUNNING`. */
  itemsProcessed: number;
  /** Last progress line, or the failure message once the job has failed. */
  message?: string | null;
  /** Principal name of whoever triggered it, or "system". */
  triggeredBy?: string | null;
  /** Server-side optimistic lock. Present on the wire; the UI ignores it. */
  version?: number;
}

/* -------------------------------------------------------------------------- */
/* Dashboard stats — GET /api/stats/dashboard                                 */
/* -------------------------------------------------------------------------- */

export interface DashboardStats {
  globalSyncs: number; // CVEs + KEVs + EPSS updated in last 7d
  activeKevCount: number; // Total size of KEV table
  highEpssCount: number; // EPSS > 0.36 updated in last 7d
  accessibleCount: number;
  globalCrit: number;
  globalHigh: number;
  globalMed: number;
  globalLow: number;

  /* ---------------------------------------------------------------------- */
  /* Actionable roll-up (Phase 1). All `long`, all scoped to actionable=true. */
  /* ---------------------------------------------------------------------- */

  /** Total actionable alerts — the headline number. */
  openActionableCount: number;
  /** reason in (KEV, KEV_AND_EPSS_HIGH). Overlaps `actionableEpssCount`. */
  actionableKevCount: number;
  /** reason in (EPSS_HIGH, KEV_AND_EPSS_HIGH). Overlaps `actionableKevCount`. */
  actionableEpssCount: number;
  /** CVE baseSeverity = CRITICAL. The four sev counts exclude unscored CVEs. */
  actionableCrit: number;
  actionableHigh: number;
  actionableMed: number;
  actionableLow: number;
  /** fixState = FIXED. */
  actionableWithFixCount: number;
  /** fixState in (NO_FIX, UNKNOWN). */
  actionableNoFixCount: number;
  /** The four exploit-maturity counts DO partition `openActionableCount`. */
  actionableExploitNone: number;
  actionableExploitPoc: number;
  actionableExploitWeaponized: number;
  actionableExploitInTheWild: number;
  /** kevDueDate < today. */
  pastKevDueCount: number;
  /** createdAt within 7 days — the trend arrow. */
  actionableCreatedLast7d: number;
}

/* -------------------------------------------------------------------------- */
/* Actionable Items — GET /api/actionable, GET /api/actionable/:id            */
/* -------------------------------------------------------------------------- */

/** Why an alert made it through the funnel. `KEV_AND_EPSS_HIGH` is its own value. */
export type ActionableReason = 'KEV' | 'EPSS_HIGH' | 'KEV_AND_EPSS_HIGH';

/** Whether a patch exists for an actionable item. */
export type FixState = 'FIXED' | 'NO_FIX' | 'UNKNOWN';

/** Where the fix version came from. */
export type FixSource = 'OSV' | 'SCANNER' | 'CPE_RANGE';

/** Public-exploit availability. Declaration order is the ordering (NONE < … < IN_THE_WILD). */
export type ExploitMaturity = 'NONE' | 'POC' | 'WEAPONIZED' | 'IN_THE_WILD';

/**
 * How confident the correlator is that an alert's component is really the
 * vulnerable one. Answers a different question than `FixSource` — this is
 * "is this really my component?", not "how good is this fix version?".
 * `EXACT` and `RANGE` are both normal, trustworthy outcomes; `HEURISTIC` is a
 * name-guess and should be called out in the UI.
 */
export type MatchConfidence = 'EXACT' | 'RANGE' | 'HEURISTIC';

/**
 * One row of `GET /api/actionable` — a `Page<ActionableItem>`. Sort is fixed
 * server-side (EPSS desc, then createdAt desc). `description` is truncated at
 * 280 chars with a trailing `…`. `kev` is a convenience boolean. Nulls arrive
 * as `null`, not omitted.
 */
export interface ActionableItem {
  /** Alert UUID — the id for `GET /api/actionable/:id`. */
  id: string;
  cveId: string;
  description: string;
  baseSeverity: BaseSeverity;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  kev: boolean;
  /** Date string, e.g. "2021-12-24". Null when the CVE is not KEV-listed. */
  kevDueDate: string | null;
  /** Mirrors KEV's field verbatim: "Known" / "Unknown" / null. */
  knownRansomwareUse: string | null;
  exploitMaturity: ExploitMaturity;
  fixState: FixState;
  fixedVersions: string | null;
  fixSource: FixSource | null;
  matchConfidence: MatchConfidence | null;
  actionableReason: ActionableReason;
  productId: string | null;
  productName: string | null;
  /** Set on an asset-derived row instead of `productId`/`productName` (Phase 4) — never both. */
  assetId: string | null;
  /** e.g. "acme/api:1.4.2". Null on a product-derived row. */
  assetName: string | null;
  componentId: string | null;
  componentName: string | null;
  componentVersion: string | null;
  componentPurl: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
}

/** The CVE block nested in an `ActionableDetail`. */
export interface ActionableDetailCve {
  id: string;
  sourceIdentifier: string | null;
  /** ISO-8601 date-time string. */
  published: string | null;
  /** ISO-8601 date-time string. */
  lastModified: string | null;
  vulnStatus: string | null;
  description: string | null;
  baseSeverity: BaseSeverity | null;
  cvssScore: number | null;
  exploitabilityScore: number | null;
  impactScore: number | null;
  cwe: string | null;
  accessVector: string | null;
  accessComplexity: string | null;
  authenticationRequired: string | null;
  confidentialityImpact: string | null;
  integrityImpact: string | null;
  availabilityImpact: string | null;
  userInteractionRequired: boolean | null;
}

/** One entry of `ActionableDetail.affectedComponents` — every alert for the same CVE. */
export interface ActionableAffectedComponent {
  alertId: string;
  componentId: string | null;
  name: string;
  version: string | null;
  purl: string | null;
  sbomId: string | null;
  productId: string | null;
  productName: string | null;
  assetId: string | null;
  /** Set alongside `assetId` on an asset entry; null on an SBOM entry. */
  assetName: string | null;
}

/** One entry of `ActionableDetail.references`. `tags` is a comma-joined string. */
export interface ActionableReference {
  url: string;
  source: string | null;
  tags: string | null;
}

/**
 * `GET /api/actionable/:id`. Resolves for non-actionable alerts too (a deep
 * link must not 404), so `actionableReason` can be null. `kev` / `epss` are
 * null when the CVE has no such row.
 */
export interface ActionableDetail {
  id: string;
  actionable: boolean;
  actionableReason: ActionableReason | null;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  exploitMaturity: ExploitMaturity;
  fixState: FixState;
  fixedVersions: string | null;
  fixSource: FixSource | null;
  matchConfidence: MatchConfidence | null;
  /**
   * `ACTIVE` on every list row (the list endpoint filters to `ACTIVE` only).
   * A deep link can resolve an `AUTO_RESOLVED` alert — one that no longer
   * matches the current scan — since this endpoint resolves any alert.
   */
  lifecycleState: 'ACTIVE' | 'AUTO_RESOLVED';
  /** Date string, e.g. "2021-12-24". */
  kevDueDate: string | null;
  knownRansomwareUse: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
  cve: ActionableDetailCve;
  affectedComponents: ActionableAffectedComponent[];
  kev: KEV | null;
  epss: EPSS | null;
  references: ActionableReference[];
}

/**
 * Query params for `GET /api/actionable` beyond `page` / `size`. `state` is
 * deliberately omitted — the backend still accepts and ignores it (Phase 7).
 * `assetId` **is** a real filter as of Phase 4 — passing an arbitrary id now
 * returns an empty page rather than the unfiltered list.
 */
export interface ActionableFilters {
  /** Alerts on SBOMs belonging to this product. */
  productId?: string;
  /** Alerts on this asset. Now a real filter (Phase 4) — no longer accepted-and-ignored. */
  assetId?: string;
  /** Exact match — `reason=KEV` does NOT include `KEV_AND_EPSS_HIGH`. */
  reason?: ActionableReason;
  /** `cvssScore >= minCvss`; unscored CVEs are excluded. */
  minCvss?: number;
  /** Exact match. */
  fixState?: FixState;
  /** At or above, by declaration order. `NONE` is a no-op. */
  minExploitMaturity?: ExploitMaturity;
  /** Exact match — no "at or above" form. */
  matchConfidence?: MatchConfidence;
}

/* -------------------------------------------------------------------------- */
/* CISA KEV — GET /api/kev                                                    */
/* -------------------------------------------------------------------------- */

/**
 * A CISA Known Exploited Vulnerability entry.
 *
 * The Angular codebase declared this twice with slightly different shapes:
 * `kev.service.ts` had the full row, while the copy in `product.service.ts`
 * (used for the intelligence link hanging off a `Vulnerability`) declared only
 * a subset. This is the union — verified against a live `GET /api/kev`, which
 * returns every field below.
 */
export interface KEV {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  /** ISO-8601 date-time string, e.g. "2026-09-03T19:00:00". */
  added: string;
  description: string;
  requiredActions: string;
  /** ISO-8601 date-time string. */
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

/* -------------------------------------------------------------------------- */
/* FIRST EPSS — GET /api/epss                                                 */
/* -------------------------------------------------------------------------- */

export interface EPSS {
  cve: string;
  /** Probability of exploitation, 0.0 – 1.0. */
  epss: number;
  /** Percentile rank relative to all other CVEs. */
  percentile: number;
  date: string;
}

/* -------------------------------------------------------------------------- */
/* NVD vulnerabilities — GET /api/nvd/search                                  */
/* -------------------------------------------------------------------------- */

/**
 * An NVD CVE record, enriched with live intelligence links.
 *
 * The backend serializes more columns than this. A live `GET /api/nvd/search`
 * row also carries: `sourceIdentifier`, `vulnStatus`, `cveTags`, `cwe`,
 * `references`, `alerts`, `cpeOperators`, the CVSS v2 access/impact vectors
 * (`accessVector`, `accessComplexity`, `authenticationRequired`,
 * `confidentialityImpact`, `integrityImpact`, `availabilityImpact`) and the
 * `canObtain*Privilege` / `userInteractionRequired` booleans. The Angular UI
 * never used them; add them here as you start rendering them.
 */
export interface Vulnerability {
  /** The CVE ID, e.g. "CVE-2024-1234". */
  id: string;
  description: string;
  baseSeverity: string;
  cvssScore: number;
  exploitabilityScore: number;
  impactScore: number;
  /** ISO-8601 date-time string. */
  published: string;
  /** ISO-8601 date-time string. */
  lastModified: string;
  // Live Intelligence Links
  kev?: KEV;
  epss?: EPSS;
}

/** Severity buckets used by `Vulnerability.baseSeverity`. */
export type BaseSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

/* -------------------------------------------------------------------------- */
/* Product catalog & SBOMs — /api/products, /api/sbom                         */
/* -------------------------------------------------------------------------- */

/**
 * A catalogued product.
 *
 * IMPORTANT for view authors: the Angular interface declared `actionableCount`
 * as required, but a live `GET /api/products` returns only `id`, `name`,
 * `description`, `createdAt` and `sboms` — the roll-up counters below are not
 * serialized today. They are all optional here so the compiler forces you to
 * guard them (`product.actionableCount ?? 0`) instead of rendering `undefined`.
 */
export interface Product {
  id: string;
  name: string;
  description: string;
  /** ISO-8601 date-time string. */
  createdAt: string;
  sboms: SBOM[];
  activeSbomStatus?: string;
  activeSbomId?: string;
  vulnerabilityCount?: number;
  /** ISO-8601 date-time string. */
  lastScanned?: string;
  actionableCount?: number;
}

/** SBOM processing state observed on the wire. */
export type SbomStatus = 'PROCESSING' | 'SCANNED' | 'FAILED' | (string & {});

export interface SBOM {
  id: string;
  /** e.g. "CycloneDX". */
  format: string;
  /** e.g. "1.6". */
  specVersion: string;
  /** Monotonic upload revision for the owning product. */
  version: number;
  active: boolean;
  status: SbomStatus;
  /** Null until the first scan completes. */
  lastScannedAt?: string | null;
  /** ISO-8601 date-time string. */
  uploadDate: string;
  totalVulnerabilities: number;
  components: SBOMComponent[];
  tools: SBOMTool[];
  /** User-supplied version label from the upload request; often null. */
  productVersion?: string | null;
  /** The SBOM's root/metadata component. Not present on every payload. */
  component?: SBOMComponent;
}

export interface SBOMTool {
  id?: string;
  group: string;
  name: string;
  version: string;
  type: string;
}

export interface SBOMComponent {
  id: string;
  name: string;
  version?: string | null;
  purl?: string | null;
  vulnerabilityAlerts: VulnerabilityAlert[];
  /** CycloneDX bom-ref. */
  bomRef?: string;
  /** e.g. "application", "library". */
  type?: string;
  description?: string | null;
  licenses?: string[];
  references?: string[];
}

/** Join between an SBOM component and a vulnerability affecting it. */
export interface VulnerabilityAlert {
  /** UUID. */
  id: string;
  component: SBOMComponent;
  vulnerability: Vulnerability;
}

/** Payload accepted by POST /api/products. */
export type CreateProductPayload = Pick<Product, 'name' | 'description'> & Partial<Product>;

/* -------------------------------------------------------------------------- */
/* Infrastructure / asset inventory — /api/assets (Phase 4)                   */
/* -------------------------------------------------------------------------- */

/** The kind of thing a scanned asset represents. */
export type AssetType = 'CONTAINER_IMAGE' | 'HOST' | 'SERVICE';

/** Asset scan lifecycle, mirrors `asset.status` on the backend. */
export type AssetStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

/** Which scanner's report last populated the asset. */
export type AssetScanner = 'Trivy' | 'Grype';

/**
 * One row of `GET /api/assets` — a `Page<AssetSummary>`. `componentCount`
 * counts only components present in the last successful scan;
 * `actionableCount` uses the exact same predicate as `/actionable`
 * (`actionable = true AND lifecycleState = ACTIVE`), so this badge and the
 * drill-down list can never disagree.
 */
export interface AssetSummary {
  id: string;
  type: AssetType;
  name: string;
  productId: string | null;
  productName: string | null;
  status: AssetStatus | null;
  scanner: AssetScanner | null;
  /** ISO-8601 date-time string. Null before the first scan completes. */
  lastScannedAt: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
  componentCount: number;
  actionableCount: number;
}

/**
 * `GET /api/assets/:id` — the summary plus declared CPEs and its actionable
 * items (a nested `Page`, `size` defaulting to 25 server-side).
 */
export interface AssetDetail extends AssetSummary {
  declaredCpes: string[];
  actionableItems: Page<ActionableItem>;
}

/** `DELETE /api/assets/:id` response — the cascade counts, since the delete is destructive. */
export interface AssetDeletionSummary {
  id: string;
  name: string;
  componentsRemoved: number;
  alertsRemoved: number;
}

/* -------------------------------------------------------------------------- */
/* Compliance reports — /api/compliance (Phase 5)                             */
/* -------------------------------------------------------------------------- */

/**
 * The verdict on one control, or on one check inside it. Mirrors
 * `ComplianceStatus.java`: three values, not a boolean, because Trivy only
 * emits a finding for a check it actually evaluated — a great many CIS Docker
 * controls are manual/operational items it cannot evaluate at all, and those
 * are `SKIP`, not a silent `PASS`.
 */
export type ComplianceStatus = 'PASS' | 'FAIL' | 'SKIP';

/**
 * A compliance report's own ingest/correlation lifecycle — mirrors
 * `DockerComplianceReport.STATUS_*`. Distinct from {@link ComplianceStatus}
 * (that's the benchmark's verdict; this is "has Secy finished processing the
 * upload").
 */
export type ComplianceReportStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

/** One control's rolled-up verdict, part of `ComplianceReportDetail.controls`. */
export interface ComplianceControl {
  id: string;
  controlId: string | null;
  name: string | null;
  severity: string | null;
  status: ComplianceStatus;
  /** How many checks under this control failed. Zero on a PASS or SKIP. */
  failedChecks: number;
}

/**
 * One configuration check in the Compliance view's misconfiguration list.
 *
 * `resolution` is the remediation text, verbatim from the benchmark — never
 * elided by the backend, and never hidden here: a compliance finding without
 * "and here is what to do about it" is a complaint, not a finding.
 */
export interface ComplianceMisconfiguration {
  id: string;
  controlId: string | null;
  controlName: string | null;
  checkId: string | null;
  avdId: string | null;
  type: string | null;
  title: string | null;
  description: string | null;
  message: string | null;
  resolution: string | null;
  severity: string | null;
  status: ComplianceStatus;
  target: string | null;
  primaryUrl: string | null;
  references: string[];
}

/**
 * One row of `GET /api/compliance/reports` — a `Page<ComplianceReportSummary>`.
 *
 * `actionableItems` counts the audited asset's current ACTIVE actionable
 * alerts (the same predicate `/actionable` applies), not this report's own
 * vulnerability line count — the report's findings are reconciled onto the
 * asset, so "how bad is this thing" is an asset question.
 */
export interface ComplianceReportSummary {
  id: string;
  /** The benchmark's own id, e.g. "docker-cis-1.6.0". Not unique — every audit repeats it. */
  benchmarkId: string | null;
  title: string | null;
  version: string | null;
  assetId: string | null;
  assetName: string | null;
  status: ComplianceReportStatus;
  passedControls: number;
  failedControls: number;
  skippedControls: number;
  totalControls: number;
  actionableItems: number;
  /** ISO-8601 date-time string. Null until the report's first scan finishes. */
  scannedAt: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
}

/**
 * `GET /api/compliance/reports/:id` — the audit, both halves: the benchmark
 * result (`controls` + paged `misconfigurations`, with remediation text) and
 * a page of the audited asset's `ActionableItem`s (same shape/sort
 * `/actionable` returns).
 */
export interface ComplianceReportDetail {
  id: string;
  benchmarkId: string | null;
  title: string | null;
  description: string | null;
  version: string | null;
  assetId: string | null;
  assetName: string | null;
  status: ComplianceReportStatus;
  passedControls: number;
  failedControls: number;
  skippedControls: number;
  totalControls: number;
  /** ISO-8601 date-time string. Null until the report's first scan finishes. */
  scannedAt: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
  relatedResources: string[];
  controls: ComplianceControl[];
  misconfigurations: Page<ComplianceMisconfiguration>;
  actionableItems: Page<ActionableItem>;
}
