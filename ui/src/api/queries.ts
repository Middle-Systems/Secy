/**
 * TanStack Query hooks for every Secy backend resource.
 *
 * View components should never call `api` / `fetch` directly — add a hook here
 * instead, so caching, invalidation and query keys stay in one place.
 *
 * Conventions:
 *  - Query keys come from `queryKeys` below. Never inline a key array.
 *  - Paged list hooks use `placeholderData: keepPreviousData`, so the grid keeps
 *    showing the previous page while the next one loads instead of flashing empty.
 *  - Mutations invalidate the keys they affect; they do NOT raise toasts. Fire
 *    those from the view (`import { toast } from 'sonner'`) so copy stays local
 *    to the screen that triggered the action.
 */
import { useEffect, useRef } from 'react';
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationOptions,
  type UseQueryOptions,
} from '@tanstack/react-query';

import { isTerminalJobStatus } from '@/lib/jobs';

import { api } from './client';
import type {
  ActionableDetail,
  ActionableFilters,
  ActionableItem,
  AssetDeletionSummary,
  AssetDetail,
  AssetSummary,
  AssetType,
  ComplianceMisconfiguration,
  ComplianceReportDetail,
  ComplianceReportSummary,
  ComplianceStatus,
  CompromiseConfidence,
  CompromiseFinding,
  CompromiseType,
  CreateProductPayload,
  CreateSourceConnectorPayload,
  DashboardStats,
  EPSS,
  Job,
  JobStatus,
  JobType,
  KEV,
  Page,
  PageParams,
  Product,
  SourceConnector,
  Vulnerability,
  VulnerabilityAlert,
} from './types';

/* -------------------------------------------------------------------------- */
/* Query keys                                                                 */
/* -------------------------------------------------------------------------- */

export const queryKeys = {
  stats: {
    all: ['stats'] as const,
    dashboard: () => [...queryKeys.stats.all, 'dashboard'] as const,
  },
  kev: {
    all: ['kev'] as const,
    page: (params: PageParams) => [...queryKeys.kev.all, 'page', params] as const,
  },
  epss: {
    all: ['epss'] as const,
    page: (params: PageParams) => [...queryKeys.epss.all, 'page', params] as const,
  },
  nvd: {
    all: ['nvd'] as const,
    search: (params: PageParams) => [...queryKeys.nvd.all, 'search', params] as const,
  },
  actionable: {
    all: ['actionable'] as const,
    page: (params: ActionablePageParams) => [...queryKeys.actionable.all, 'page', params] as const,
    detail: (id: string) => [...queryKeys.actionable.all, 'detail', id] as const,
  },
  compromise: {
    all: ['compromise'] as const,
    list: (params: CompromiseListParams) => [...queryKeys.compromise.all, 'list', params] as const,
    detail: (id: string) => [...queryKeys.compromise.all, 'detail', id] as const,
  },
  products: {
    all: ['products'] as const,
    list: () => [...queryKeys.products.all, 'list'] as const,
    detail: (id: string) => [...queryKeys.products.all, 'detail', id] as const,
  },
  sbom: {
    all: ['sbom'] as const,
    vulnerabilities: (sbomId: string) =>
      [...queryKeys.sbom.all, 'vulnerabilities', sbomId] as const,
  },
  jobs: {
    all: ['jobs'] as const,
    detail: (jobId: string) => [...queryKeys.jobs.all, 'detail', jobId] as const,
    list: (params: JobListParams) => [...queryKeys.jobs.all, 'list', params] as const,
  },
  assets: {
    all: ['assets'] as const,
    list: (params: AssetListParams) => [...queryKeys.assets.all, 'list', params] as const,
    detail: (id: string) => [...queryKeys.assets.all, 'detail', id] as const,
  },
  compliance: {
    all: ['compliance'] as const,
    reports: (params: ComplianceReportListParams) =>
      [...queryKeys.compliance.all, 'reports', params] as const,
    report: (id: string) => [...queryKeys.compliance.all, 'report', id] as const,
    misconfigurations: (id: string, params: ComplianceMisconfigurationListParams) =>
      [...queryKeys.compliance.all, 'misconfigurations', id, params] as const,
  },
  connectors: {
    all: ['connectors'] as const,
    list: (params: ConnectorListParams) => [...queryKeys.connectors.all, 'list', params] as const,
    detail: (id: string) => [...queryKeys.connectors.all, 'detail', id] as const,
  },
} as const;

/** Options a caller may override on any of the query hooks below. */
type QueryOverrides<TData> = Omit<UseQueryOptions<TData, Error>, 'queryKey' | 'queryFn'>;
type MutationOverrides<TData, TVariables> = Omit<
  UseMutationOptions<TData, Error, TVariables>,
  'mutationFn'
>;

/** Default page size — matches the Spring controllers' `size` default. */
export const DEFAULT_PAGE_SIZE = 15;

/* -------------------------------------------------------------------------- */
/* Ingestion jobs                                                             */
/* -------------------------------------------------------------------------- */

/** Filters accepted by `GET /api/jobs`. */
export interface JobListParams {
  page: number;
  size: number;
  type?: JobType;
  status?: JobStatus;
}

/** How often `useJob` re-reads a job that has not finished yet. */
export const JOB_POLL_INTERVAL_MS = 2_000;

/**
 * Which cached data a finished job of each type has just invalidated. A job type may touch more
 * than one cache — SBOM_UPLOAD's ingest changes the product's SBOM list, the alerts derived from it
 * and the dashboard roll-up all at once — so every entry is a list of query keys, not one.
 */
const FEED_KEYS: Record<JobType, readonly (readonly unknown[])[]> = {
  KEV: [queryKeys.kev.all],
  EPSS: [queryKeys.epss.all],
  NVD: [queryKeys.nvd.all],
  // The exploit index has no browser view of its own; a finished pull only
  // matters because it re-derives every alert's exploitMaturity.
  EXPLOIT: [queryKeys.actionable.all],
  // Neither OSV nor the CVE List has a browser view of its own either — a finished pull
  // feeds correlation (OSV) or cveStatus/CVSS/SSVC (CVE List), both surfaced only through
  // the actionable list and its re-enrichment, never a dedicated table.
  OSV: [queryKeys.actionable.all],
  CVE_LIST: [queryKeys.actionable.all],
  // An upload's components/alerts only exist once its SBOM_UPLOAD job succeeds — see
  // useUploadSbom, which (like useIngestKev et al.) only invalidates the job list immediately.
  SBOM_UPLOAD: [queryKeys.products.all, queryKeys.sbom.all, queryKeys.stats.all],
  // Same shape as SBOM_UPLOAD (Phase 4): the asset's components/alerts only exist once its
  // ASSET_SCAN job succeeds. `stats.all` is invalidated unconditionally below regardless.
  ASSET_SCAN: [queryKeys.assets.all, queryKeys.actionable.all],
  // Same shape again (Phase 5): a compliance report's controls/misconfigurations only exist
  // once its COMPLIANCE_SCAN job succeeds, and it audits an asset — the same asset Infrastructure
  // shows, correlated through the same funnel — so assets and actionable both need invalidating too.
  COMPLIANCE_SCAN: [queryKeys.compliance.all, queryKeys.actionable.all, queryKeys.assets.all],
  // Phase 6: a finished feed pull only updates the mirrored corpus (browsable through
  // ThreatController, not surfaced in this UI) — it does NOT retro-scan existing SBOMs/assets
  // (PHASE6-CONTRACT §9, deferred), so findings only appear on the next correlation of a scope.
  // Invalidated anyway so a manual re-scan afterwards reads fresh data, and because detection
  // may have already fired inline off an unrelated upload that raced the ingest.
  MALICIOUS_PACKAGES: [queryKeys.actionable.all, queryKeys.compromise.all, queryKeys.stats.all],
  MALWARE_HASHES: [queryKeys.actionable.all, queryKeys.compromise.all, queryKeys.stats.all],
  // Phase 6b: a sync creates/updates Products and their SBOMs (one repo -> one Product, the exact
  // manual-SPDX-upload ingest path), which flow into the actionable funnel exactly like SBOM_UPLOAD's
  // components/alerts do — so this invalidates the same keys SBOM_UPLOAD does, plus the connector's
  // own list (status/lastSyncedAt only change once the sync actually finishes).
  CONNECTOR_SYNC: [
    queryKeys.connectors.all,
    queryKeys.products.all,
    queryKeys.actionable.all,
    queryKeys.stats.all,
  ],
};

/**
 * GET /api/jobs/:jobId — poll one ingestion job.
 *
 * Disabled until `jobId` is truthy, so a component can call it before an
 * ingest has been kicked off. While the job is `QUEUED` or `RUNNING` it
 * refetches every {@link JOB_POLL_INTERVAL_MS}; once it reaches a terminal
 * status the interval is dropped, so a finished job costs nothing.
 *
 * When a job lands on `SUCCEEDED` this also invalidates the feed it filled and
 * the dashboard stats — that is the moment the ingested rows actually exist,
 * not the moment the ingest was enqueued.
 */
export function useJob(
  jobId: string | undefined,
  { poll = true }: { poll?: boolean } = {},
  options?: QueryOverrides<Job>,
) {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.jobs.detail(jobId ?? ''),
    queryFn: () => api.get<Job>(`/jobs/${jobId}`),
    enabled: Boolean(jobId),
    refetchInterval: (q) => {
      if (!poll) return false;
      return isTerminalJobStatus(q.state.data?.status) ? false : JOB_POLL_INTERVAL_MS;
    },
    ...options,
  });

  // Invalidate once per job, not once per poll after it succeeds.
  const invalidatedFor = useRef<string | null>(null);
  const { status, type } = query.data ?? {};

  useEffect(() => {
    if (!jobId || status !== 'SUCCEEDED' || !type) return;
    if (invalidatedFor.current === jobId) return;
    invalidatedFor.current = jobId;
    for (const queryKey of FEED_KEYS[type]) {
      void queryClient.invalidateQueries({ queryKey });
    }
    void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
  }, [jobId, status, type, queryClient]);

  return query;
}

/** GET /api/jobs?page&size&type&status — recent-first list of ingestion jobs. */
export function useJobs(
  { page = 0, size = 5, type, status }: Partial<JobListParams> = {},
  options?: QueryOverrides<Page<Job>>,
) {
  const params: JobListParams = { page, size, type, status };
  return useQuery({
    queryKey: queryKeys.jobs.list(params),
    queryFn: () => api.get<Page<Job>>('/jobs', { query: { page, size, type, status } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/* -------------------------------------------------------------------------- */
/* Dashboard stats                                                            */
/* -------------------------------------------------------------------------- */

/** GET /api/stats/dashboard */
export function useDashboardStats(options?: QueryOverrides<DashboardStats>) {
  return useQuery({
    queryKey: queryKeys.stats.dashboard(),
    queryFn: () => api.get<DashboardStats>('/stats/dashboard'),
    ...options,
  });
}

/* -------------------------------------------------------------------------- */
/* CISA KEV                                                                   */
/* -------------------------------------------------------------------------- */

/** GET /api/kev?page&size&search */
export function useKevPage(
  { page = 0, size = DEFAULT_PAGE_SIZE, search = '' }: Partial<PageParams> = {},
  options?: QueryOverrides<Page<KEV>>,
) {
  const params: PageParams = { page, size, search };
  return useQuery({
    queryKey: queryKeys.kev.page(params),
    queryFn: () => api.get<Page<KEV>>('/kev', { query: { page, size, search } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * POST /api/kev/ingest — queues a pull of the latest CISA KEV catalog.
 *
 * Resolves as soon as the job is enqueued, with the `Job` to poll through
 * {@link useJob}; it does not wait for the catalog to download. Posting again
 * while a KEV ingest is already queued or running returns that same job, so a
 * double click cannot stack two pulls.
 *
 * Only the job list is invalidated here — the KEV table has not changed yet.
 * `useJob` invalidates the feed when the job actually succeeds.
 */
export function useIngestKev(options?: MutationOverrides<Job, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job>('/kev/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* FIRST EPSS                                                                 */
/* -------------------------------------------------------------------------- */

/** GET /api/epss?page&size&search */
export function useEpssPage(
  { page = 0, size = DEFAULT_PAGE_SIZE, search = '' }: Partial<PageParams> = {},
  options?: QueryOverrides<Page<EPSS>>,
) {
  const params: PageParams = { page, size, search };
  return useQuery({
    queryKey: queryKeys.epss.page(params),
    queryFn: () => api.get<Page<EPSS>>('/epss', { query: { page, size, search } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * POST /api/epss/ingest — queues a pull of the latest FIRST EPSS scores.
 * Returns the `Job` to poll; see {@link useIngestKev} for the full contract.
 */
export function useIngestEpss(options?: MutationOverrides<Job, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job>('/epss/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* NVD                                                                        */
/* -------------------------------------------------------------------------- */

/** GET /api/nvd/search?search&page&size */
export function useNvdSearch(
  { search = '', page = 0, size = DEFAULT_PAGE_SIZE }: Partial<PageParams> = {},
  options?: QueryOverrides<Page<Vulnerability>>,
) {
  const params: PageParams = { page, size, search };
  return useQuery({
    queryKey: queryKeys.nvd.search(params),
    queryFn: () => api.get<Page<Vulnerability>>('/nvd/search', { query: { search, page, size } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * POST /api/nvd/ingest — queues a pull of CVE records from the NVD feed.
 * Returns the `Job` to poll; see {@link useIngestKev} for the full contract.
 *
 * This is the one that most needed to stop being synchronous: a full NVD pull
 * runs for minutes, and the old `GET` held the request open for all of it.
 */
export function useIngestNvd(options?: MutationOverrides<Job, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job>('/nvd/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Actionable Items                                                           */
/* -------------------------------------------------------------------------- */

/** Query params for `GET /api/actionable` — paging plus the filter contract. */
export interface ActionablePageParams extends ActionableFilters {
  page: number;
  size: number;
}

/**
 * GET /api/actionable — the funnel output, paged.
 *
 * Sort is fixed server-side (EPSS score desc, then `createdAt` desc), so there
 * is no `sort` param. Filters (`productId` / `reason` / `minCvss` / `fixState`
 * / `minExploitMaturity` / `matchConfidence`) are passed straight through;
 * `undefined` entries are dropped by the client. Keeps the previous page
 * visible while the next loads.
 */
export function useActionablePage(
  { page = 0, size = DEFAULT_PAGE_SIZE, ...filters }: Partial<ActionablePageParams> = {},
  options?: QueryOverrides<Page<ActionableItem>>,
) {
  const params: ActionablePageParams = { page, size, ...filters };
  return useQuery({
    queryKey: queryKeys.actionable.page(params),
    queryFn: () =>
      api.get<Page<ActionableItem>>('/actionable', { query: { page, size, ...filters } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * GET /api/actionable/:id — full detail for one alert.
 *
 * Disabled until `id` is truthy, so a component can call it before a row has
 * been selected. Resolves for non-actionable alerts too (deep links must not
 * 404).
 */
export function useActionableDetail(
  id: string | undefined,
  options?: QueryOverrides<ActionableDetail>,
) {
  return useQuery({
    queryKey: queryKeys.actionable.detail(id ?? ''),
    queryFn: () => api.get<ActionableDetail>(`/actionable/${id}`),
    enabled: Boolean(id),
    ...options,
  });
}

/* -------------------------------------------------------------------------- */
/* Supply-chain compromise findings (Phase 6)                                 */
/* -------------------------------------------------------------------------- */

/** Query params for `GET /api/compromise` beyond `page` / `size`. */
export interface CompromiseListParams {
  page: number;
  size: number;
  type?: CompromiseType;
  confidence?: CompromiseConfidence;
  productId?: string;
  assetId?: string;
  componentId?: string;
  /** Defaults to `ACTIVE` server-side when omitted. */
  lifecycleState?: 'ACTIVE' | 'AUTO_RESOLVED';
}

/**
 * GET /api/compromise — the compromise findings corpus, paged and filtered.
 *
 * Sort is fixed server-side (confidence, then IOC freshness desc, then
 * createdAt desc — the same fixed order `/actionable` uses for its compromise
 * tier). `componentId` matches either an SBOM or asset component, so an id
 * lifted off an `/actionable` row works without knowing which kind it is.
 * Keeps the previous page visible while the next loads, same as
 * {@link useActionablePage}.
 */
export function useCompromiseFindings(
  { page = 0, size = DEFAULT_PAGE_SIZE, ...filters }: Partial<CompromiseListParams> = {},
  options?: QueryOverrides<Page<CompromiseFinding>>,
) {
  const params: CompromiseListParams = { page, size, ...filters };
  return useQuery({
    queryKey: queryKeys.compromise.list(params),
    queryFn: () =>
      api.get<Page<CompromiseFinding>>('/compromise', { query: { page, size, ...filters } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * GET /api/compromise/:id — full detail for one compromise finding. List row
 * and detail body are the same shape (see {@link CompromiseFinding}).
 *
 * Disabled until `id` is truthy. **This is the hook an `/actionable` row with
 * `itemType: 'COMPROMISE'` must route its detail panel to** — its `id` is a
 * `compromise_finding` id, not a `vulnerability_alert` id, and
 * `GET /actionable/:id` 404s on it (PHASE6-CONTRACT §4.5).
 */
export function useCompromiseFindingDetail(
  id: string | undefined,
  options?: QueryOverrides<CompromiseFinding>,
) {
  return useQuery({
    queryKey: queryKeys.compromise.detail(id ?? ''),
    queryFn: () => api.get<CompromiseFinding>(`/compromise/${id}`),
    enabled: Boolean(id),
    ...options,
  });
}

/**
 * POST /api/threat/ingest/malicious-packages — queues a mirror of the OpenSSF
 * Malicious Packages corpus (~310 MB, full refresh every run). Returns the
 * `Job` to poll; see {@link useIngestKev} for the full enqueue → poll → settle
 * contract.
 */
export function useIngestMaliciousPackages(options?: MutationOverrides<Job, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job>('/threat/ingest/malicious-packages'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * POST /api/threat/ingest/malware-hashes — queues a pull of the abuse.ch
 * MalwareBazaar CSV export. Returns the `Job` to poll; see {@link useIngestKev}
 * for the full contract.
 */
export function useIngestMalwareHashes(options?: MutationOverrides<Job, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job>('/threat/ingest/malware-hashes'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * POST /api/threat/ingest — convenience wrapper that queues *both* threat
 * feeds at once and resolves with both jobs, in order
 * `[MALICIOUS_PACKAGES, MALWARE_HASHES]`. Prefer the two feed-specific hooks
 * above when a caller wants to poll/label each independently (e.g. two
 * separate {@link IngestButton}s); this one is for a single "sync everything"
 * control that doesn't need per-feed progress.
 */
export function useIngestThreat(options?: MutationOverrides<Job[], void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<Job[]>('/threat/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Product catalog                                                            */
/* -------------------------------------------------------------------------- */

/** GET /api/products */
export function useProducts(options?: QueryOverrides<Product[]>) {
  return useQuery({
    queryKey: queryKeys.products.list(),
    queryFn: () => api.get<Product[]>('/products'),
    ...options,
  });
}

/** POST /api/products */
export function useCreateProduct(options?: MutationOverrides<Product, CreateProductPayload>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (product: CreateProductPayload) => api.post<Product>('/products', product),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.products.all });
      options?.onSuccess?.(...args);
    },
  });
}

/** DELETE /api/products/:id */
export function useDeleteProduct(options?: MutationOverrides<void, string>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/products/${id}`),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.products.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* SBOMs                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * GET /api/sbom/:sbomId/vulnerabilities
 *
 * The endpoint answers 204 (no body) when an SBOM has no alerts, so the result
 * is normalized to an empty array. Disabled until `sbomId` is truthy, which
 * makes it safe to call from a modal before a row has been selected.
 */
export function useSbomVulnerabilities(
  sbomId: string | undefined,
  options?: QueryOverrides<VulnerabilityAlert[]>,
) {
  return useQuery({
    queryKey: queryKeys.sbom.vulnerabilities(sbomId ?? ''),
    queryFn: async () => {
      const alerts = await api.get<VulnerabilityAlert[] | undefined>(
        `/sbom/${sbomId}/vulnerabilities`,
      );
      return alerts ?? [];
    },
    enabled: Boolean(sbomId),
    ...options,
  });
}

export interface UploadSbomVariables {
  productId: string;
  /** Parsed CycloneDX or SPDX (2.2/2.3 JSON) document. */
  sbom: unknown;
  productVersion?: string;
}

/**
 * POST /api/sbom/:productId/sboms?productVersion=… — queues an SBOM upload.
 *
 * Format detection/validation happens synchronously on the backend (a document that is neither
 * CycloneDX nor SPDX 2.2/2.3 is still a plain `400` from this call, before anything is queued), but
 * ingesting its components, correlating alerts and scanning all happen in a background
 * `SBOM_UPLOAD` job. This resolves with that `Job` — poll it with {@link useJob} — not the finished
 * `SBOM`; see {@link IngestButton} / {@link useIngestKev} for the same enqueue → poll → settle shape.
 *
 * Only the job list is invalidated here — the product's SBOM list has not changed yet. `useJob`
 * invalidates `products` / `sbom` / `stats` (via `FEED_KEYS.SBOM_UPLOAD`) once the job actually
 * succeeds.
 */
export function useUploadSbom(options?: MutationOverrides<Job, UploadSbomVariables>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ productId, sbom, productVersion = 'Unknown' }: UploadSbomVariables) =>
      api.post<Job>(`/sbom/${productId}/sboms`, sbom, { query: { productVersion } }),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Infrastructure / asset inventory (Phase 4)                                 */
/* -------------------------------------------------------------------------- */

/** Filters accepted by `GET /api/assets`. */
export interface AssetListParams {
  page: number;
  size: number;
  type?: AssetType;
  productId?: string;
}

/**
 * GET /api/assets?page&size&type&productId — the asset inventory, paged.
 * Ordered by name server-side. Keeps the previous page visible while the next
 * loads, same as {@link useKevPage} / {@link useActionablePage}.
 */
export function useAssets(
  { page = 0, size = DEFAULT_PAGE_SIZE, type, productId }: Partial<AssetListParams> = {},
  options?: QueryOverrides<Page<AssetSummary>>,
) {
  const params: AssetListParams = { page, size, type, productId };
  return useQuery({
    queryKey: queryKeys.assets.list(params),
    queryFn: () =>
      api.get<Page<AssetSummary>>('/assets', { query: { page, size, type, productId } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * GET /api/assets/:id — full detail for one asset, including its declared
 * CPEs and a page of its actionable items. Disabled until `id` is truthy.
 */
export function useAssetDetail(id: string | undefined, options?: QueryOverrides<AssetDetail>) {
  return useQuery({
    queryKey: queryKeys.assets.detail(id ?? ''),
    queryFn: () => api.get<AssetDetail>(`/assets/${id}`),
    enabled: Boolean(id),
    ...options,
  });
}

/**
 * DELETE /api/assets/:id — cascades to the asset's components and alerts
 * (deliberate; see PHASE4-CONTRACT §5). Resolves with the `AssetDeletionSummary`
 * so the caller can show the counts in a toast. Invalidates the asset list, the
 * dashboard roll-up and the actionable list (the asset's alerts are gone too).
 */
export function useDeleteAsset(options?: MutationOverrides<AssetDeletionSummary, string>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<AssetDeletionSummary>(`/assets/${id}`),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assets.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.actionable.all });
      options?.onSuccess?.(...args);
    },
  });
}

export interface ScanAssetVariables {
  /** Raw `trivy image -f json` (or `grype -o json`) report body, sent verbatim. */
  report: unknown;
  /** Defaults to the report's own artifact name on the backend when omitted. */
  name?: string;
  /** Default `CONTAINER_IMAGE` on the backend when omitted. */
  type?: AssetType;
  productId?: string;
}

/**
 * POST /api/assets/scan/trivy — queues a Trivy image/filesystem scan.
 *
 * Format validation happens synchronously (a document that isn't a Trivy
 * vulnerability report — including one posted to the wrong endpoint — is a
 * plain `400` from this call, before anything is queued); ingesting
 * components and correlating alerts happens in a background `ASSET_SCAN` job.
 * Resolves with that `Job` — poll it with {@link useJob} — same enqueue → poll
 * → settle shape as {@link useUploadSbom}.
 */
export function useScanAssetTrivy(options?: MutationOverrides<Job, ScanAssetVariables>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ report, name, type, productId }: ScanAssetVariables) =>
      api.post<Job>('/assets/scan/trivy', report, { query: { name, type, productId } }),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * POST /api/assets/scan/grype — queues a Grype scan. Same contract as
 * {@link useScanAssetTrivy}, against the Grype-shaped endpoint.
 */
export function useScanAssetGrype(options?: MutationOverrides<Job, ScanAssetVariables>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ report, name, type, productId }: ScanAssetVariables) =>
      api.post<Job>('/assets/scan/grype', report, { query: { name, type, productId } }),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Compliance reports (Phase 5)                                               */
/* -------------------------------------------------------------------------- */

/** Filters accepted by `GET /api/compliance/reports`. */
export interface ComplianceReportListParams {
  page: number;
  size: number;
  assetId?: string;
}

/**
 * GET /api/compliance/reports?page&size&assetId — reports newest first, each
 * row carrying its control pass/fail/skip counts and the audited asset's
 * current actionable count. Keeps the previous page visible while the next
 * loads, same as {@link useAssets}.
 */
export function useComplianceReports(
  { page = 0, size = DEFAULT_PAGE_SIZE, assetId }: Partial<ComplianceReportListParams> = {},
  options?: QueryOverrides<Page<ComplianceReportSummary>>,
) {
  const params: ComplianceReportListParams = { page, size, assetId };
  return useQuery({
    queryKey: queryKeys.compliance.reports(params),
    queryFn: () =>
      api.get<Page<ComplianceReportSummary>>('/compliance/reports', {
        query: { page, size, assetId },
      }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/**
 * GET /api/compliance/reports/:id — the control breakdown, a first page of
 * misconfigurations and a first page of the audited asset's actionable items.
 * Disabled until `id` is truthy, same as {@link useAssetDetail}. Deeper paging
 * through the misconfiguration list goes through {@link useComplianceMisconfigurations}
 * instead of re-fetching this.
 */
export function useComplianceReportDetail(
  id: string | undefined,
  options?: QueryOverrides<ComplianceReportDetail>,
) {
  return useQuery({
    queryKey: queryKeys.compliance.report(id ?? ''),
    queryFn: () => api.get<ComplianceReportDetail>(`/compliance/reports/${id}`),
    enabled: Boolean(id),
    ...options,
  });
}

/** Filters accepted by `GET /api/compliance/reports/:id/misconfigurations`. */
export interface ComplianceMisconfigurationListParams {
  page: number;
  size: number;
  status?: ComplianceStatus;
}

/**
 * GET /api/compliance/reports/:id/misconfigurations?page&size&status — the
 * same page `GET /compliance/reports/:id` embeds, for paging deeper (or
 * filtering by PASS/FAIL/SKIP) without re-fetching the whole report. Disabled
 * until `id` is truthy.
 */
export function useComplianceMisconfigurations(
  id: string | undefined,
  { page = 0, size = 10, status }: Partial<ComplianceMisconfigurationListParams> = {},
  options?: QueryOverrides<Page<ComplianceMisconfiguration>>,
) {
  const params: ComplianceMisconfigurationListParams = { page, size, status };
  return useQuery({
    queryKey: queryKeys.compliance.misconfigurations(id ?? '', params),
    queryFn: () =>
      api.get<Page<ComplianceMisconfiguration>>(`/compliance/reports/${id}/misconfigurations`, {
        query: { page, size, status },
      }),
    enabled: Boolean(id),
    placeholderData: keepPreviousData,
    ...options,
  });
}

export interface UploadComplianceReportVariables {
  /** Raw `trivy --compliance <spec> -f json` report body, sent verbatim. */
  report: unknown;
  /** Required unless the document names its own artifact (most `--compliance` runs do not). */
  name?: string;
  /** Default `CONTAINER_IMAGE` on the backend when omitted. */
  type?: AssetType;
  productId?: string;
}

/**
 * POST /api/compliance/reports?name&type&productId — validates synchronously
 * (a document that isn't a Trivy compliance report — including one posted to
 * the wrong endpoint — is a plain `400` from this call, before anything is
 * queued), then queues persistence + correlation as a background
 * `COMPLIANCE_SCAN` job. Resolves with that `Job` — poll it with {@link useJob}
 * — same enqueue → poll → settle shape as {@link useScanAssetTrivy}.
 */
export function useUploadComplianceReport(
  options?: MutationOverrides<Job, UploadComplianceReportVariables>,
) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ report, name, type, productId }: UploadComplianceReportVariables) =>
      api.post<Job>('/compliance/reports', report, { query: { name, type, productId } }),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * POST /api/compliance/reports/:id/scan — re-scan an already-ingested report:
 * replays its persisted findings through correlation and enrichment again
 * (e.g. after a KEV/EPSS/OSV refresh) without re-uploading the document.
 * Resolves with the `Job` to poll, same contract as {@link useUploadComplianceReport}.
 */
export function useRescanComplianceReport(options?: MutationOverrides<Job, string>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<Job>(`/compliance/reports/${id}/scan`),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Source connectors (Phase 6b)                                               */
/* -------------------------------------------------------------------------- */

/** Filters accepted by `GET /api/connectors`. */
export interface ConnectorListParams {
  page: number;
  size: number;
}

/**
 * GET /api/connectors?page&size — connectors newest first, each carrying its
 * own `status`/`lastSyncedAt` from its most recent sync. Keeps the previous
 * page visible while the next loads, same as {@link useAssets}.
 */
export function useConnectors(
  { page = 0, size = DEFAULT_PAGE_SIZE }: Partial<ConnectorListParams> = {},
  options?: QueryOverrides<Page<SourceConnector>>,
) {
  const params: ConnectorListParams = { page, size };
  return useQuery({
    queryKey: queryKeys.connectors.list(params),
    queryFn: () => api.get<Page<SourceConnector>>('/connectors', { query: { page, size } }),
    placeholderData: keepPreviousData,
    ...options,
  });
}

/** GET /api/connectors/:id — one connector. Disabled until `id` is truthy. */
export function useConnectorDetail(
  id: string | undefined,
  options?: QueryOverrides<SourceConnector>,
) {
  return useQuery({
    queryKey: queryKeys.connectors.detail(id ?? ''),
    queryFn: () => api.get<SourceConnector>(`/connectors/${id}`),
    enabled: Boolean(id),
    ...options,
  });
}

/**
 * POST /api/connectors — registers a connector but does not trigger a sync;
 * call {@link useSyncConnector} for that. Invalidates the connector list on
 * success.
 */
export function useCreateConnector(
  options?: MutationOverrides<SourceConnector, CreateSourceConnectorPayload>,
) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (connector: CreateSourceConnectorPayload) =>
      api.post<SourceConnector>('/connectors', connector),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.connectors.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * POST /api/connectors/:id/sync — queues a `CONNECTOR_SYNC` job that
 * enumerates the connector's repos and pulls each one's dependency-graph
 * SBOM. Resolves with the `Job` to poll — same enqueue → poll → settle shape
 * as {@link useScanAssetTrivy}; the real cache invalidation (connectors,
 * products, actionable, stats) happens via `useJob`'s `FEED_KEYS` mechanism
 * once the job actually succeeds.
 */
export function useSyncConnector(options?: MutationOverrides<Job, string>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<Job>(`/connectors/${id}/sync`),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.jobs.all });
      options?.onSuccess?.(...args);
    },
  });
}

/**
 * DELETE /api/connectors/:id — removes the connector row only. Does NOT
 * delete the Products/SBOMs it created (see `SourceConnectorController`) —
 * those are real inventory now, independent of whichever connector
 * introduced them. Invalidates the connector list on success.
 */
export function useDeleteConnector(options?: MutationOverrides<void, string>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/connectors/${id}`),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.connectors.all });
      options?.onSuccess?.(...args);
    },
  });
}
