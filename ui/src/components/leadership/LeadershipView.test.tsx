import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';

import type { LeadershipMetrics } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useLeadershipMetrics = vi.fn();

vi.mock('@/api/queries', () => ({
  useLeadershipMetrics: (...args: unknown[]) => useLeadershipMetrics(...args),
}));

import { LeadershipView } from './LeadershipView';

function metrics(overrides: Partial<LeadershipMetrics> = {}): LeadershipMetrics {
  return {
    generatedAt: '2026-09-30T12:00:00',
    scoringModelVersion: 'm1i.1',
    findingsBySeverity: { critical: 2, high: 3, medium: 1, low: 0, unknown: 0, total: 6 },
    openFindingsByType: { VULNERABILITY: 6, COMPROMISE: 1 },
    kevExposure: {
      kevFindingCount: 2,
      kevPastDueCount: 1,
      kevByLifecycleStage: { DEPLOYED: 2 },
      productsWithKevCount: 1,
    },
    currentRisk: { maxRiskScore: 92.5, topFindingId: 'alert-1', scoredFindingCount: 6, unscoredFindingCount: 0 },
    riskTrend: { available: false, note: 'No risk-score history is stored.' },
    weeklyFlow: Array.from({ length: 12 }, (_, i) => ({
      weekStart: `2026-0${(i % 9) + 1}-01`,
      newFindings: i,
      actionItemsCreated: i,
      actionItemsResolved: 0,
    })),
    mttr: {
      basis: 'ACTION_ITEMS',
      windowDays: 90,
      resolvedCount: 2,
      meanHours: 36,
      medianHours: 36,
      fixVerifiedCount: 1,
      awaitingVerificationCount: 0,
      note: 'Measures time from creation to resolution.',
    },
    sbomStageCoverage: {
      summary: {
        productCount: 3,
        productsWithNoSbom: 1,
        productsLegacyOnly: 1,
        productsStaged: 1,
        productsWithAllFourStages: 0,
        productsWithStage: { SOURCE: 1, BUILD: 0, ANALYZED: 0, DEPLOYED: 1 },
      },
      products: [
        {
          productId: 'prod-1',
          productName: 'Acme Web',
          mode: 'STAGED',
          stagesPresent: ['SOURCE', 'DEPLOYED'],
          stagesMissing: ['BUILD', 'ANALYZED'],
          hasUnstagedActiveSbom: false,
          maxRiskScore: 92.5,
        },
      ],
    },
    ...overrides,
  };
}

describe('LeadershipView', () => {
  it('renders the headline tiles and coverage table', () => {
    useLeadershipMetrics.mockReturnValue({ data: metrics(), isPending: false, isError: false });

    renderWithProviders(<LeadershipView />);

    expect(screen.getByText('Leadership')).toBeInTheDocument();
    expect(screen.getByText('Acme Web')).toBeInTheDocument();
    expect(screen.getByText('STAGED')).toBeInTheDocument();
    expect(screen.getByText(/No risk-score history is stored/)).toBeInTheDocument();
  });

  it('shows a loading state', () => {
    useLeadershipMetrics.mockReturnValue({ data: undefined, isPending: true, isError: false });

    renderWithProviders(<LeadershipView />);

    expect(screen.getByText(/Loading leadership metrics/)).toBeInTheDocument();
  });
});
