import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { EPSS, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useEpssPage = vi.fn();
const useJobs = vi.fn();
// Ingests are background jobs now: the mutation resolves with the queued Job,
// and the button polls `useJob` from there.
const mutateAsync = vi.fn().mockResolvedValue({
  id: 'job-1',
  type: 'EPSS',
  status: 'QUEUED',
  createdAt: '2026-09-05T12:00:00',
  itemsProcessed: 0,
});

vi.mock('@/api/queries', () => ({
  useEpssPage: (...args: unknown[]) => useEpssPage(...args),
  useIngestEpss: () => ({ mutateAsync, isPending: false }),
  useJob: () => ({ data: undefined, isPending: false, isError: false }),
  useJobs: (...args: unknown[]) => useJobs(...args),
}));

const toastError = vi.fn();
const toastSuccess = vi.fn();
vi.mock('sonner', () => ({
  toast: {
    error: (...a: unknown[]) => toastError(...a),
    success: (...a: unknown[]) => toastSuccess(...a),
    info: vi.fn(),
  },
}));

import { EpssDatabaseView } from './EpssDatabaseView';

function epss(overrides: Partial<EPSS> = {}): EPSS {
  return {
    cve: 'CVE-2026-1234',
    epss: 0.25,
    percentile: 0.94,
    date: '2026-09-01',
    ...overrides,
  };
}

function page(content: EPSS[]): Page<EPSS> {
  return {
    content,
    totalElements: content.length,
    totalPages: 1,
    number: 0,
    size: 15,
    numberOfElements: content.length,
    first: true,
    last: true,
    empty: content.length === 0,
  };
}

function mockQuery(over: Record<string, unknown>) {
  // No ingestion history by default — RecentIngestions renders nothing.
  useJobs.mockReturnValue({ data: undefined, isPending: false, isError: false });
  useEpssPage.mockReturnValue({
    data: undefined,
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

afterEach(() => {
  vi.clearAllMocks();
});

describe('EpssDatabaseView', () => {
  it('renders a row with probability, percentile framing and the risk pill', () => {
    mockQuery({ data: page([epss()]) });
    renderWithProviders(<EpssDatabaseView />);

    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    expect(screen.getByText('25.00%')).toBeInTheDocument();
    expect(screen.getByText('94th pct')).toBeInTheDocument();
    expect(screen.getByText('Critical Probability')).toBeInTheDocument();
  });

  it('shows the empty message', () => {
    mockQuery({ data: page([]) });
    renderWithProviders(<EpssDatabaseView />);
    expect(screen.getByText('No EPSS records found.')).toBeInTheDocument();
  });

  it('shows an inline error and toasts when the query fails with no data', () => {
    mockQuery({ isError: true, data: undefined });
    renderWithProviders(<EpssDatabaseView />);
    expect(screen.getByText('Unable to load EPSS scores')).toBeInTheDocument();
    expect(toastError).toHaveBeenCalled();
  });

  it('toasts on a successful manual refresh', async () => {
    const refetch = vi.fn().mockResolvedValue({ error: null });
    mockQuery({ data: page([epss()]), refetch });
    renderWithProviders(<EpssDatabaseView />);

    await userEvent.click(screen.getByRole('button', { name: 'Reload table data' }));

    await waitFor(() => {
      expect(refetch).toHaveBeenCalled();
      expect(toastSuccess).toHaveBeenCalledWith('Exploit Prediction Scoring table updated');
    });
  });
});
