import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { Page, SourceConnector } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useConnectors = vi.fn();
const useDeleteConnector = vi.fn();
const useCreateConnector = vi.fn();
const useSyncConnector = vi.fn();

vi.mock('@/api/queries', () => ({
  useConnectors: (...args: unknown[]) => useConnectors(...args),
  useDeleteConnector: (...args: unknown[]) => useDeleteConnector(...args),
  useCreateConnector: (...args: unknown[]) => useCreateConnector(...args),
  useSyncConnector: (...args: unknown[]) => useSyncConnector(...args),
}));

// The real hook polls a job through `useJob`; for these tests only the
// "does clicking Sync call through to the mutation" wiring matters, so this
// stub just runs `ingest()` synchronously and reports as idle.
const useIngestJobMock = vi.fn(({ ingest }: { ingest: () => Promise<unknown> }) => ({
  start: () => ingest(),
  running: false,
  enqueuing: false,
  status: undefined,
  itemsProcessed: 0,
  message: undefined,
  jobId: undefined,
}));

vi.mock('@/components/jobs/useIngestJob', () => ({
  useIngestJob: (...args: [{ ingest: () => Promise<unknown> }]) => useIngestJobMock(...args),
}));

const toastSuccess = vi.fn();
const toastError = vi.fn();
vi.mock('sonner', () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
    info: vi.fn(),
  },
}));

import { ConnectorsView } from './ConnectorsView';

function connector(overrides: Partial<SourceConnector> = {}): SourceConnector {
  return {
    id: 'conn-1',
    type: 'GITHUB',
    name: 'Acme org',
    scope: 'acme-corp',
    repoAllowlist: [],
    status: 'COMPLETED',
    lastSyncedAt: '2026-09-10T12:00:00',
    jobId: null,
    createdAt: '2026-09-01T00:00:00',
    ...overrides,
  };
}

const failedConnector = connector({
  id: 'conn-2',
  name: 'Beta scope',
  scope: 'beta-org',
  repoAllowlist: ['beta-org/api', 'beta-org/web'],
  status: 'FAILED',
});

const neverSyncedConnector = connector({
  id: 'conn-3',
  name: 'Gamma scope',
  scope: 'gamma-user',
  status: null,
  lastSyncedAt: null,
});

function page(content: SourceConnector[]): Page<SourceConnector> {
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

function mockConnectorsPage(over: Record<string, unknown> = {}) {
  useConnectors.mockReturnValue({
    data: page([connector(), failedConnector, neverSyncedConnector]),
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

const deleteConnectorMutateAsync = vi.fn();
const createConnectorMutateAsync = vi.fn();
const syncConnectorMutateAsync = vi.fn();

beforeEach(() => {
  deleteConnectorMutateAsync.mockReset();
  createConnectorMutateAsync.mockReset();
  syncConnectorMutateAsync.mockReset();
  useDeleteConnector.mockReturnValue({
    mutateAsync: deleteConnectorMutateAsync,
    isPending: false,
  });
  useCreateConnector.mockReturnValue({
    mutateAsync: createConnectorMutateAsync,
    isPending: false,
  });
  useSyncConnector.mockReturnValue({
    mutateAsync: syncConnectorMutateAsync,
    isPending: false,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('ConnectorsView', () => {
  it('renders connector rows with the right status treatment', () => {
    mockConnectorsPage();
    renderWithProviders(<ConnectorsView />);

    expect(screen.getByText('Acme org')).toBeInTheDocument();
    expect(screen.getByText('Beta scope')).toBeInTheDocument();
    expect(screen.getByText('Gamma scope')).toBeInTheDocument();

    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.getByText('Never synced')).toBeInTheDocument();

    // Empty allowlist reads as "All repos" (two rows have one); a populated one shows the count.
    expect(screen.getAllByText('All repos')).toHaveLength(2);
    expect(screen.getByText('2 repos')).toBeInTheDocument();
  });

  it('shows an empty state when there are no connectors yet', () => {
    mockConnectorsPage({ data: page([]) });
    renderWithProviders(<ConnectorsView />);

    expect(screen.getByText(/No connectors yet/)).toBeInTheDocument();
  });

  it('adds a connector with a parsed repo allowlist', async () => {
    mockConnectorsPage();
    createConnectorMutateAsync.mockResolvedValue(connector());
    renderWithProviders(<ConnectorsView />);

    await userEvent.click(screen.getByRole('button', { name: /add connector/i }));

    await userEvent.type(screen.getByLabelText('Name'), 'New Org');
    await userEvent.type(screen.getByLabelText('GitHub org or user'), 'new-org');
    await userEvent.type(
      screen.getByLabelText(/repo allowlist/i),
      'new-org/api, new-org/web\nnew-org/api',
    );

    await userEvent.click(screen.getByRole('button', { name: 'Add connector' }));

    await waitFor(() => {
      expect(createConnectorMutateAsync).toHaveBeenCalledWith({
        type: 'GITHUB',
        name: 'New Org',
        scope: 'new-org',
        repoAllowlist: ['new-org/api', 'new-org/web'],
      });
    });
    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('New Org'));
    });
  });

  it('triggers a sync via the row Sync now button', async () => {
    mockConnectorsPage();
    syncConnectorMutateAsync.mockResolvedValue({ id: 'job-1' });
    renderWithProviders(<ConnectorsView />);

    await userEvent.click(screen.getByRole('button', { name: 'Sync Acme org now' }));

    await waitFor(() => {
      expect(syncConnectorMutateAsync).toHaveBeenCalledWith('conn-1');
    });
  });

  it('deletes a connector after confirmation, with a toast noting products/SBOMs are untouched', async () => {
    mockConnectorsPage();
    deleteConnectorMutateAsync.mockResolvedValue(undefined);
    renderWithProviders(<ConnectorsView />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete Acme org' }));

    expect(screen.getByText('Delete “Acme org”?')).toBeInTheDocument();
    expect(screen.getByText(/does NOT remove the products/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteConnectorMutateAsync).toHaveBeenCalledWith('conn-1');
    });
    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('Acme org'));
    });
  });

  it('cancelling the delete confirmation does not call the mutation', async () => {
    mockConnectorsPage();
    renderWithProviders(<ConnectorsView />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete Acme org' }));
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(deleteConnectorMutateAsync).not.toHaveBeenCalled();
  });
});
