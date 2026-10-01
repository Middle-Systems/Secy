import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';

import type { ActionItem, OwnedProduct, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useActionItemsPage = vi.fn();
const useMyOwnedProducts = vi.fn();
const useActionItemDetail = vi.fn();
const usePatchActionItem = vi.fn();
const useDisputeFinding = vi.fn();

vi.mock('@/api/queries', () => ({
  useActionItemsPage: (...args: unknown[]) => useActionItemsPage(...args),
  useMyOwnedProducts: (...args: unknown[]) => useMyOwnedProducts(...args),
  useActionItemDetail: (...args: unknown[]) => useActionItemDetail(...args),
  usePatchActionItem: (...args: unknown[]) => usePatchActionItem(...args),
  useDisputeFinding: (...args: unknown[]) => useDisputeFinding(...args),
}));

// The finding-detail drilldown panel is exercised by its own component tests.
vi.mock('@/components/actionable/ActionableDetailPanel', () => ({
  ActionableDetailPanel: () => null,
}));

import { MyWorkView } from './MyWorkView';

function page(content: ActionItem[]): Page<ActionItem> {
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

function item(overrides: Partial<ActionItem> = {}): ActionItem {
  return {
    id: 'item-1',
    title: 'Upgrade log4j',
    productId: 'prod-1',
    productName: 'Acme Web',
    assetId: null,
    assetName: null,
    status: 'OPEN',
    recordedStatus: 'OPEN',
    derivation: null,
    reopened: false,
    riskAcceptanceExpired: false,
    awaitingVerification: false,
    fixVerified: false,
    assigneeId: null,
    assigneeName: null,
    findingCount: 1,
    remainingFindingCount: 1,
    findingCountsByType: { VULNERABILITY: 1 },
    score: { maxRiskScore: 82.5, topFindingId: 'alert-1', scoredFindingCount: 1, unscoredFindingCount: 0 },
    fixSummary: { remainingWithKnownFix: 1, remainingWithoutKnownFix: 0 },
    createdAt: '2026-09-01T00:00:00',
    createdById: 'user-1',
    updatedAt: '2026-09-02T00:00:00',
    resolvedAt: null,
    ...overrides,
  };
}

describe('MyWorkView', () => {
  it('renders the owned action items', () => {
    useActionItemsPage.mockReturnValue({ data: page([item()]), isPending: false });
    useMyOwnedProducts.mockReturnValue({ data: [{ productId: 'prod-1', productName: 'Acme Web' } as OwnedProduct] });
    useActionItemDetail.mockReturnValue({ data: undefined, isPending: false });
    usePatchActionItem.mockReturnValue({ mutateAsync: vi.fn(), isPending: false });
    useDisputeFinding.mockReturnValue({ mutateAsync: vi.fn(), isPending: false });

    renderWithProviders(<MyWorkView />);

    expect(screen.getByText('Upgrade log4j')).toBeInTheDocument();
    expect(screen.getByText('Acme Web')).toBeInTheDocument();
  });

  it('shows the no-owned-products empty state', () => {
    useActionItemsPage.mockReturnValue({ data: page([]), isPending: false });
    useMyOwnedProducts.mockReturnValue({ data: [] });
    useActionItemDetail.mockReturnValue({ data: undefined, isPending: false });
    usePatchActionItem.mockReturnValue({ mutateAsync: vi.fn(), isPending: false });
    useDisputeFinding.mockReturnValue({ mutateAsync: vi.fn(), isPending: false });

    renderWithProviders(<MyWorkView />);

    expect(
      screen.getByText(/don't own any products yet/i),
    ).toBeInTheDocument();
  });
});
