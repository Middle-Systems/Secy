import { QueryClient } from '@tanstack/react-query';

import { ApiError } from '@/api/client';

/**
 * Shared TanStack Query client.
 *
 * Exported separately from `main.tsx` so tests (and any future prefetching)
 * can build their own client with the same defaults.
 */
export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Feed data changes on ingest, not continuously — don't refetch on every
        // window focus, and treat data as fresh for a minute.
        staleTime: 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          // A 4xx will not fix itself; only retry transient failures.
          if (error instanceof ApiError && error.status < 500) return false;
          return failureCount < 2;
        },
      },
      mutations: {
        retry: false,
      },
    },
  });
}

export const queryClient = createQueryClient();
