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
  CreateProductPayload,
  DashboardStats,
  EPSS,
  Job,
  JobStatus,
  JobType,
  KEV,
  Page,
  PageParams,
  Product,
  SBOM,
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

/** Which feed's cached data a finished job has just invalidated. */
const FEED_KEYS: Record<JobType, readonly unknown[]> = {
  KEV: queryKeys.kev.all,
  EPSS: queryKeys.epss.all,
  NVD: queryKeys.nvd.all,
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
    void queryClient.invalidateQueries({ queryKey: FEED_KEYS[type] });
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
  /** Parsed CycloneDX document. */
  sbom: unknown;
  productVersion?: string;
}

/**
 * POST /api/sbom/:productId/sboms?productVersion=…
 *
 * Uploads a CycloneDX SBOM, which the backend ingests, scans and marks active.
 */
export function useUploadSbom(options?: MutationOverrides<SBOM, UploadSbomVariables>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ productId, sbom, productVersion = 'Unknown' }: UploadSbomVariables) =>
      api.post<SBOM>(`/sbom/${productId}/sboms`, sbom, { query: { productVersion } }),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.products.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.sbom.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
      options?.onSuccess?.(...args);
    },
  });
}
