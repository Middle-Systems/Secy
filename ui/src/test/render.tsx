import type { ReactNode } from 'react';
import { QueryClientProvider } from '@tanstack/react-query';
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
  type AnyRoute,
} from '@tanstack/react-router';
import { render, type RenderOptions } from '@testing-library/react';

import { createQueryClient } from '@/lib/query-client';
import { routeTree } from '@/routeTree';

/**
 * Render a plain component with the app's providers (no router).
 * Use this for anything that does not contain a `<Link>` or read route state.
 */
export function renderWithProviders(ui: ReactNode, options?: RenderOptions) {
  const queryClient = createQueryClient();
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>, options);
}

/**
 * Mount the whole app (shell + routes) at a given URL, using an in-memory
 * history so tests can navigate without a browser.
 */
export function renderApp(initialPath = '/dashboard') {
  const queryClient = createQueryClient();
  const router = createRouter({
    routeTree: routeTree as AnyRoute,
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  });

  const result = render(
    <QueryClientProvider client={queryClient}>
      {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
      <RouterProvider router={router as any} />
    </QueryClientProvider>,
  );

  return { ...result, router, queryClient };
}
