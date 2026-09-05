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
