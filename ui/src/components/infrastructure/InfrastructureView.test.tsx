import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { AssetSummary, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useAssets = vi.fn();
const deleteAssetMutateAsync = vi.fn();
const useDeleteAsset = vi.fn();

vi.mock('@/api/queries', () => ({
  useAssets: (...args: unknown[]) => useAssets(...args),
  useDeleteAsset: (...args: unknown[]) => useDeleteAsset(...args),
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

// Both drilldowns are exercised by their own tests; stub them here so this
// file stays focused on the list + row-level delete behaviour.
vi.mock('./AssetDetailPanel', () => ({ AssetDetailPanel: () => null }));
vi.mock('./ScanAssetModal', () => ({ ScanAssetModal: () => null }));

import { InfrastructureView } from './InfrastructureView';

function asset(overrides: Partial<AssetSummary> = {}): AssetSummary {
  return {
    id: 'asset-1',
    type: 'CONTAINER_IMAGE',
    name: 'acme/api:1.4.2',
    productId: 'prod-1',
    productName: 'Acme API',
    status: 'COMPLETED',
    scanner: 'Trivy',
    lastScannedAt: '2026-09-10T12:00:00',
    createdAt: '2026-09-01T00:00:00',
    componentCount: 42,
    actionableCount: 3,
    ...overrides,
  };
}

const hostAsset = asset({
  id: 'asset-2',
  type: 'HOST',
  name: 'db-01.internal',
  productId: null,
  productName: null,
  status: 'FAILED',
  scanner: 'Grype',
  componentCount: 10,
  actionableCount: 0,
});

function page(content: AssetSummary[]): Page<AssetSummary> {
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

function mockAssetsPage(over: Record<string, unknown> = {}) {
  useAssets.mockReturnValue({
    data: page([asset(), hostAsset]),
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

beforeEach(() => {
  deleteAssetMutateAsync.mockReset();
  useDeleteAsset.mockReturnValue({ mutateAsync: deleteAssetMutateAsync, isPending: false });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('InfrastructureView', () => {
  it('renders asset rows with type, status, scanner and actionable count', () => {
    mockAssetsPage();
    renderWithProviders(<InfrastructureView />);

    expect(screen.getByText('acme/api:1.4.2')).toBeInTheDocument();
    expect(screen.getByText('db-01.internal')).toBeInTheDocument();

    expect(screen.getByText('Container image')).toBeInTheDocument();
    expect(screen.getByText('Host')).toBeInTheDocument();

    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();

    expect(screen.getByText('Trivy')).toBeInTheDocument();
    expect(screen.getByText('Grype')).toBeInTheDocument();

    // headline actionable counts
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('shows an empty state when there are no assets yet', () => {
    mockAssetsPage({ data: page([]) });
    renderWithProviders(<InfrastructureView />);

    expect(screen.getByText(/No assets yet/)).toBeInTheDocument();
  });

  it('deletes an asset after confirmation and shows the removal counts in a toast', async () => {
    mockAssetsPage();
    deleteAssetMutateAsync.mockResolvedValue({
      id: 'asset-1',
      name: 'acme/api:1.4.2',
      componentsRemoved: 42,
      alertsRemoved: 3,
    });
    renderWithProviders(<InfrastructureView />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete acme/api:1.4.2' }));

    expect(screen.getByText('Delete “acme/api:1.4.2”?')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteAssetMutateAsync).toHaveBeenCalledWith('asset-1');
    });
    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('acme/api:1.4.2'));
    });
  });

  it('cancelling the delete confirmation does not call the mutation', async () => {
    mockAssetsPage();
    renderWithProviders(<InfrastructureView />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete acme/api:1.4.2' }));
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(deleteAssetMutateAsync).not.toHaveBeenCalled();
  });
});
