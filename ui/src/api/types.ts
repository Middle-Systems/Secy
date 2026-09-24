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
  | 'COMPLIANCE_SCAN'
  | 'MALICIOUS_PACKAGES'
  | 'MALWARE_HASHES'
  | 'CONNECTOR_SYNC';

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

  /* ---------------------------------------------------------------------- */
  /* Supply-chain compromise roll-up (Phase 6). Scoped to ACTIVE findings.  */
  /* Deliberately NOT folded into `openActionableCount` — see PHASE6        */
  /* contract §8: a compromise finding has no severity/fix/exploit band, so */
  /* it gets its own tile rather than silently breaking those breakdowns.   */
  /* `GET /actionable`'s totalElements DOES include both — the Actionable   */
  /* screen's row count is openActionableCount + compromiseFindingCount.    */
  /* ---------------------------------------------------------------------- */

  /** Active `compromise_finding` rows — the headline for the compromise tile. */
  compromiseFindingCount: number;
  /** confidence = CONFIRMED — the feed named this exact artefact. */
  compromiseConfirmedCount: number;
  /** confidence = INVESTIGATE — decayed by IOC aging. Still counted in `compromiseFindingCount`. */
  compromiseInvestigateCount: number;
  /** createdAt within 7 days — the trend arrow for the tile. */
  compromiseCreatedLast7d: number;
}

/* -------------------------------------------------------------------------- */
/* Actionable Items — GET /api/actionable, GET /api/actionable/:id            */
/* -------------------------------------------------------------------------- */

/**
 * Why an item made it through the funnel. `KEV_AND_EPSS_HIGH` is its own value.
 * `COMPROMISE` (Phase 6) is never stored on a `vulnerability_alert` — it is
 * derived at response time for a `compromise_finding` row; the existence of
 * the finding *is* the promotion, so none of the CVE-based reasons apply.
 */
export type ActionableReason = 'KEV' | 'EPSS_HIGH' | 'KEV_AND_EPSS_HIGH' | 'COMPROMISE';

/**
 * The `GET /actionable` union discriminator (Phase 6). Always present, never
 * null — including on rows that predate Phase 6. A `VULNERABILITY` row is a
 * `vulnerability_alert` (CVE against a component), detail at
 * `GET /actionable/:id`. A `COMPROMISE` row is a `compromise_finding` (a
 * known-bad artefact, no CVE), detail at `GET /compromise/:id` — see
 * {@link CompromiseFinding} and `useCompromiseFindingDetail`.
 */
export type ActionableItemType = 'VULNERABILITY' | 'COMPROMISE';

/** What kind of known-bad thing a compromise finding matched. */
export type CompromiseType = 'MALICIOUS_PACKAGE' | 'MALWARE_HASH';

/**
 * How firmly Secy believes the operator is actually shipping the known-bad
 * thing. `CONFIRMED` — the feed's own statement covers this exact artefact
 * with no inference. `LIKELY` — reaching the artefact needed an inference
 * (e.g. a bounded version range, or no version to test at all). `INVESTIGATE`
 * — the evidence has decayed past `secy.compromise.ioc-stale-after`; written
 * by the nightly IOC-aging sweep. Deliberately not {@link MatchConfidence}:
 * that answers "is this really my component?" for a CVE correlation, this
 * answers "how sure are we that you are compromised", and has a third,
 * decayed state with no counterpart there.
 */
export type CompromiseConfidence = 'CONFIRMED' | 'LIKELY' | 'INVESTIGATE';

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
 * One row of `GET /api/actionable` — a `Page<ActionableItem>`. Since Phase 6
 * this is a **typed union** over two source tables (`vulnerability_alert` and
 * `compromise_finding`), discriminated by {@link ActionableItem.itemType}.
 * Every Phase 1-5 field keeps its exact meaning and is `null` on a
 * `COMPROMISE` row (`kev` is `false` rather than null); the `compromiseType`
 * family of fields is `null` on a `VULNERABILITY` row. A client that ignores
 * `itemType` reads a compromise row as a vulnerability row with a null
 * `cveId` — wrong, but not dangerous.
 *
 * Sort is fixed server-side: every compromise row is ranked above every
 * vulnerability row (compromise tier: confidence, then IOC freshness, then
 * newest; vulnerability tier: EPSS desc, then createdAt desc, unchanged from
 * Phase 1). `description` is truncated at 280 chars with a trailing `…` on a
 * vulnerability row. Nulls arrive as `null`, not omitted.
 */
export interface ActionableItem {
  /**
   * The row id — a `vulnerability_alert` id on a `VULNERABILITY` row, a
   * `compromise_finding` id on a `COMPROMISE` row. **Which detail endpoint
   * this feeds depends on `itemType`**: `GET /actionable/:id` for
   * `VULNERABILITY`, `GET /compromise/:id` for `COMPROMISE` — the former 404s
   * on a compromise id. See `useActionableDetail` / `useCompromiseFindingDetail`.
   */
  id: string;
  /** The union discriminator. Always set, never null — including on pre-Phase-6 rows. */
  itemType: ActionableItemType;
  /** Null on a `COMPROMISE` row, which has no CVE. */
  cveId: string | null;
  /** CVE description (truncated), or the finding's summary on a compromise row. */
  description: string;
  /** NVD severity band, or always `CRITICAL` on a compromise row. */
  baseSeverity: BaseSeverity;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  /** Always `false` on a compromise row (not just null — it's a real boolean field). */
  kev: boolean;
  /** Date string, e.g. "2021-12-24". Null when the CVE is not KEV-listed, or on a compromise row. */
  kevDueDate: string | null;
  /** Mirrors KEV's field verbatim: "Known" / "Unknown" / null. Null on a compromise row. */
  knownRansomwareUse: string | null;
  /** Null on a compromise row. */
  exploitMaturity: ExploitMaturity | null;
  /** Null on a compromise row — malware is removed, not "fixed" in a later version. */
  fixState: FixState | null;
  fixedVersions: string | null;
  fixSource: FixSource | null;
  /** Null on a compromise row, which reports `compromiseConfidence` instead. */
  matchConfidence: MatchConfidence | null;
  /** `COMPROMISE` on a compromise row — see {@link ActionableReason}. */
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

  /* ------------------------------------------------------------------ */
  /* Compromise-only fields (Phase 6). Null on a VULNERABILITY row.      */
  /* ------------------------------------------------------------------ */

  /** `MALICIOUS_PACKAGE` / `MALWARE_HASH`. Compromise rows only. */
  compromiseType: CompromiseType | null;
  /** `CONFIRMED` / `LIKELY` / `INVESTIGATE` — the primary sort within the compromise tier. */
  compromiseConfidence: CompromiseConfidence | null;
  /** The feed name, e.g. "OpenSSF Malicious Packages". */
  compromiseSource: string | null;
  /** The feed's id for the indicator — a `MAL-…` id, or a SHA-256. */
  iocId: string | null;
  /** What of yours matched: the component's PURL, or the digest. */
  matchedOn: string | null;
  /** ISO-8601 date-time string. When the feed first saw the indicator. */
  iocFirstSeen: string | null;
  /** ISO-8601 date-time string. When the feed last saw it — what IOC aging measures against. */
  iocLastSeen: string | null;
  /** The feed's own 0-1 conviction about the indicator, when it states one. */
  iocConfidence: number | null;

  /** ISO-8601 date-time string. */
  createdAt: string;

  /* ------------------------------------------------------------------ */
  /* Triage fields (Phase 7). Orthogonal to the KEV/EPSS/compromise      */
  /* funnel logic above — populated identically on both arms of the      */
  /* union. Absent only on a payload from before Phase 7 shipped.        */
  /* ------------------------------------------------------------------ */

  /** Person-driven triage state. Defaults to `OPEN` for a row that has never been touched. */
  triageState: TriageState;
  /** UUID of the assigned user, or null when unassigned. */
  assigneeId: string | null;
  /** The assignee's display name (falls back to email server-side), or null when unassigned. */
  assigneeName: string | null;
  /** ISO-8601 date-time string. Set only while `triageState === 'SNOOZED'`. */
  snoozedUntil: string | null;
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
 *
 * **Cross-arm exclusion (Phase 6, PHASE6-CONTRACT §4.8):** a filter only one
 * arm can satisfy excludes the *other* arm entirely, from `totalElements` as
 * well as `content` — the server enforces this, the client just needs to
 * present a sensible combination. `confidence` excludes every vulnerability
 * row; `minCvss` / `fixState` / `minExploitMaturity` / `matchConfidence`
 * exclude every compromise row. `itemType=COMPROMISE` and `reason=COMPROMISE`
 * are equivalent.
 */
export interface ActionableFilters {
  /** Alerts on SBOMs belonging to this product. */
  productId?: string;
  /** Alerts on this asset. Now a real filter (Phase 4) — no longer accepted-and-ignored. */
  assetId?: string;
  /** Exact match — `reason=KEV` does NOT include `KEV_AND_EPSS_HIGH`. `COMPROMISE` excludes every vulnerability row. */
  reason?: ActionableReason;
  /** `cvssScore >= minCvss`; unscored CVEs are excluded. Excludes every compromise row (Phase 6). */
  minCvss?: number;
  /** Exact match. Excludes every compromise row (Phase 6). */
  fixState?: FixState;
  /** At or above, by declaration order. `NONE` is a no-op. Excludes every compromise row (Phase 6). */
  minExploitMaturity?: ExploitMaturity;
  /** Exact match — no "at or above" form. Excludes every compromise row (Phase 6). */
  matchConfidence?: MatchConfidence;
  /** Restrict to one arm of the union (Phase 6). Omit to see both, merged and ranked. */
  itemType?: ActionableItemType;
  /** Exact match on a compromise finding's confidence (Phase 6). Excludes every vulnerability row. */
  confidence?: CompromiseConfidence;
  /**
   * Exact match on the person-driven triage state (Phase 7). Omit for the
   * default view: hides `RESOLVED`, `FALSE_POSITIVE`, and a `SNOOZED` row
   * whose `snoozedUntil` hasn't passed yet. Applies to both arms of the union.
   */
  state?: TriageState;
}

/* -------------------------------------------------------------------------- */
/* Supply-chain compromise findings — GET /api/compromise (Phase 6)           */
/* -------------------------------------------------------------------------- */

/**
 * `GET /api/compromise` and `GET /api/compromise/:id` — the **same shape** for
 * both a list row and the detail body. A finding's "detail" is just its feed
 * write-up and provenance (`details` / `origins` / `referencesJson`), two
 * extra strings, so splitting it into a separate detail type would cost a
 * second type and endpoint to save a couple hundred bytes per row.
 *
 * A compromise finding is a distinct table from `vulnerability_alert` — it has
 * no CVE and never will, so none of the CVSS/EPSS/KEV/fix machinery applies.
 * `severity` is always `"CRITICAL"`; there is no severity knob per the
 * contract. `referencesJson` is passed through **unparsed** on the wire —
 * parse it defensively when rendering, never assume it's valid JSON.
 */
export interface CompromiseFinding {
  id: string;
  type: CompromiseType;
  confidence: CompromiseConfidence;
  /** Always "CRITICAL" — fixed, not configurable. */
  severity: string;
  /** The feed name, e.g. "OpenSSF Malicious Packages" / "abuse.ch MalwareBazaar". */
  source: string;
  /** The feed's id for the indicator — a `MAL-…` id, or the SHA-256. */
  iocId: string;
  /** What of yours matched: the component's PURL, or the digest. */
  matchedOn: string;
  /** The feed's one-line description. */
  summary: string | null;
  /** The feed's write-up — the most useful thing in the drawer for a malicious package. Null for a hash. */
  details: string | null;
  /** Who reported it — malicious-packages origin sources, or the MalwareBazaar submitter. */
  origins: string | null;
  /** The feed record's `references[]` array, verbatim JSON — unparsed. Null when the record carried none. */
  referencesJson: string | null;
  /** ISO-8601 date-time string. When the feed first saw the indicator. */
  iocFirstSeen: string | null;
  /** ISO-8601 date-time string. When the feed last saw it — what IOC aging measures against. */
  iocLastSeen: string | null;
  /** The feed's own 0-1 conviction, when it states one. */
  iocConfidence: number | null;
  /**
   * ISO-8601 date-time string, or null if IOC aging never demoted this
   * finding. Non-null next to `confidence: "INVESTIGATE"` is how the UI
   * explains *why* a finding is only worth investigating.
   */
  agedAt: string | null;
  /** `ACTIVE` on every list row by default; pass `lifecycleState=AUTO_RESOLVED` to see history. */
  lifecycleState: 'ACTIVE' | 'AUTO_RESOLVED';
  /** Null on an asset finding. */
  productId: string | null;
  productName: string | null;
  /** Null on an SBOM finding. Exactly one of `productId`/`assetId` is normally set. */
  assetId: string | null;
  assetName: string | null;
  componentId: string | null;
  componentName: string | null;
  componentVersion: string | null;
  componentPurl: string | null;
  /** ISO-8601 date-time string. When the finding was first raised. */
  createdAt: string;
  /** ISO-8601 date-time string. When detection last reproduced it. */
  lastSeenAt: string | null;
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

/* -------------------------------------------------------------------------- */
/* Source connectors — /api/connectors (Phase 6b)                             */
/* -------------------------------------------------------------------------- */

/** The kind of connector — which provider `scope` is read against. */
export type SourceConnectorType = 'GITHUB' | 'AWS' | 'AZURE';

/**
 * A connector's own sync lifecycle, mirrors `SourceConnector.STATUS_*` on the
 * backend. The wire value is `null` before the first sync ever runs — the
 * connector was created but nothing has been fetched yet.
 */
export type SourceConnectorStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

/**
 * Where Secy should look for inventory on its own, agentlessly — a GitHub
 * org/user whose repos are enumerated and each repo's dependency-graph SBOM
 * pulled through the same path a manual SPDX upload takes, an AWS region
 * whose EC2/ECR/Lambda resources are enumerated and scanned via Inspector2,
 * or an Azure subscription whose VMs/ACR registries are enumerated and
 * scanned via Defender for Cloud.
 *
 * Deliberately carries no credential: the token/key pair is read server-side
 * (`SECY_GITHUB_TOKEN` / `secy.aws.*` / `secy.azure.*`), never entered in the
 * UI — one instance-wide credential per provider, never per connector.
 */
export interface SourceConnector {
  id: string;
  type: SourceConnectorType;
  /** Operator-given label, e.g. "Acme org". */
  name: string;
  /** What `scope` means depends on `type`: a GitHub org/user login, an AWS region, or an Azure subscription id. */
  scope: string;
  /** `owner/repo` names to restrict a GitHub sync to. Empty means every repo under `scope`. Not used by AWS/Azure. */
  repoAllowlist: string[];
  /** Null until the first sync ever runs. */
  status: SourceConnectorStatus | null;
  /** ISO-8601 date-time string. Null until the first sync finishes. */
  lastSyncedAt: string | null;
  /** The `CONNECTOR_SYNC` job currently (or most recently) syncing this connector. */
  jobId: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
}

/** `POST /api/connectors` body — does not trigger a sync. */
export type CreateSourceConnectorPayload = Pick<SourceConnector, 'type' | 'name' | 'scope'> & {
  repoAllowlist?: string[];
};

/* -------------------------------------------------------------------------- */
/* Triage workflow — PATCH /api/actionable(/:id), POST /api/actionable/:id/   */
/* comments, GET /api/actionable/:id/history, GET /api/users (Phase 7)        */
/* -------------------------------------------------------------------------- */

/**
 * Person-driven triage state, orthogonal to the KEV/EPSS/compromise funnel
 * logic that decides whether an item is actionable in the first place — an
 * item can be actionable and sit at any of these. Applies identically to both
 * arms of the `/actionable` union.
 */
export type TriageState = 'OPEN' | 'ACKNOWLEDGED' | 'SNOOZED' | 'RESOLVED' | 'FALSE_POSITIVE';

/**
 * One entry of `GET /api/actionable/:id/history`, oldest first on the wire
 * (reverse client-side to show newest-first). `fromState`/`toState` both null
 * means a pure comment with no state change.
 */
export interface TriageEvent {
  id: string;
  fromState: TriageState | null;
  toState: TriageState | null;
  comment: string | null;
  /** Null on an event with no attributable user (defensive — every event from a live PATCH/comment has one). */
  changedById: string | null;
  changedByName: string | null;
  /** ISO-8601 date-time string. */
  createdAt: string;
}

/**
 * Response of `PATCH /api/actionable/:id` — the triage fields alone, echoed
 * back after the patch, not the full item.
 */
export interface TriageStatusResponse {
  id: string;
  itemType: ActionableItemType;
  triageState: TriageState;
  assigneeId: string | null;
  assigneeName: string | null;
  snoozedUntil: string | null;
}

/**
 * Body of `PATCH /api/actionable/:id` — a partial patch. The backend
 * (`TriageService.updateState`) treats an **omitted or `null`** field as
 * "leave unchanged", not "clear it" — a plain Java record can't tell the two
 * apart on the wire — so there is deliberately no way to unassign or clear a
 * snooze date through this endpoint, only to set one. Works for both a
 * `vulnerability_alert` id and a `compromise_finding` id (unlike
 * `GET /actionable/:id`, which is vulnerability-only).
 */
export interface TriagePatchPayload {
  state?: TriageState;
  assigneeId?: string;
  /** ISO-8601 date-time string. */
  snoozedUntil?: string;
  comment?: string;
}

/** Body of `POST /api/actionable/:id/comments`. `comment` is required, max 4096 characters. */
export interface TriageCommentPayload {
  comment: string;
}

/**
 * Body of the bulk `PATCH /api/actionable` (no id in the path). Same
 * set-only-no-clear contract as {@link TriagePatchPayload} — omitting
 * `assigneeId` leaves every id's current assignee unchanged; there is no bulk
 * unassign.
 */
export interface BulkTriagePatchPayload {
  ids: string[];
  state?: TriageState;
  assigneeId?: string;
}

/** Response of the bulk `PATCH /api/actionable`. */
export interface BulkTriageResponse {
  updated: number;
}

/** `GET /api/users` — every enabled user, for the assignee picker. */
export interface User {
  id: string;
  email: string;
  displayName: string | null;
}

/**
 * The triage-only slice of an `ActionableItem` — what `ActionableDetailPanel`
 * seeds its triage controls with. Neither `GET /actionable/:id` nor
 * `GET /compromise/:id` echo these back (they live on the `/actionable` list
 * row and on {@link TriageStatusResponse} only), so the panel's caller passes
 * the row it already has.
 */
export type TriageSnapshot = Pick<
  ActionableItem,
  'triageState' | 'assigneeId' | 'assigneeName' | 'snoozedUntil'
>;
