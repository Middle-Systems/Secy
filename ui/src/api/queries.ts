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
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationOptions,
  type UseQueryOptions,
} from '@tanstack/react-query';

import { api } from './client';
import type {
  CreateProductPayload,
  DashboardStats,
  EPSS,
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

/** GET /api/kev/ingest — pulls the latest CISA KEV catalog. */
export function useIngestKev(options?: MutationOverrides<void, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.get<void>('/kev/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.kev.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
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

/** GET /api/epss/ingest — pulls the latest FIRST EPSS scores. */
export function useIngestEpss(options?: MutationOverrides<void, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.get<void>('/epss/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.epss.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
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
 * GET /api/nvd/ingest — pulls CVE records from the NVD feed.
 *
 * Note: the Angular `NvdService` requested this as a relative `api/nvd/ingest`
 * (no leading slash), which only worked from the app root. Fixed here.
 */
export function useIngestNvd(options?: MutationOverrides<void, void>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.get<void>('/nvd/ingest'),
    ...options,
    onSuccess: (...args) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.nvd.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats.all });
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
