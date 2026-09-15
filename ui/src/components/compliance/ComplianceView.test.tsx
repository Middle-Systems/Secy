import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { ComplianceReportSummary, Job, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useComplianceReports = vi.fn();
const rescanMutateAsync = vi.fn();
const useRescanComplianceReport = vi.fn();

vi.mock('@/api/queries', () => ({
  useComplianceReports: (...args: unknown[]) => useComplianceReports(...args),
  useRescanComplianceReport: (...args: unknown[]) => useRescanComplianceReport(...args),
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
// file stays focused on the list + row-level re-scan behaviour.
vi.mock('./ComplianceReportDetailPanel', () => ({ ComplianceReportDetailPanel: () => null }));
vi.mock('./UploadComplianceReportModal', () => ({ UploadComplianceReportModal: () => null }));
vi.mock('@/components/infrastructure/AssetDetailPanel', () => ({ AssetDetailPanel: () => null }));

import { ComplianceView } from './ComplianceView';

function report(overrides: Partial<ComplianceReportSummary> = {}): ComplianceReportSummary {
  return {
    id: 'report-1',
    benchmarkId: 'docker-cis-1.6.0',
    title: 'CIS Docker Benchmark',
    version: '1.6.0',
    assetId: 'asset-1',
    assetName: 'acme/api:1.4.2',
    status: 'COMPLETED',
    passedControls: 32,
    failedControls: 8,
    skippedControls: 4,
    totalControls: 44,
    actionableItems: 3,
    scannedAt: '2026-09-10T12:00:00',
    createdAt: '2026-09-01T00:00:00',
    ...overrides,
  };
}

const failingReport = report({
  id: 'report-2',
  title: 'CIS Kubernetes Benchmark',
  benchmarkId: 'k8s-cis-1.24',
  assetId: 'asset-2',
  assetName: 'db-01.internal',
  passedControls: 10,
  failedControls: 20,
  skippedControls: 0,
  totalControls: 30,
  actionableItems: 0,
});

function page(content: ComplianceReportSummary[]): Page<ComplianceReportSummary> {
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

function mockReportsPage(over: Record<string, unknown> = {}) {
  useComplianceReports.mockReturnValue({
    data: page([report(), failingReport]),
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

function job(overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    type: 'COMPLIANCE_SCAN',
    status: 'QUEUED',
    createdAt: '2026-09-11T12:00:00',
    itemsProcessed: 0,
    ...overrides,
  };
}

beforeEach(() => {
  rescanMutateAsync.mockReset();
  useRescanComplianceReport.mockReturnValue({ mutateAsync: rescanMutateAsync, isPending: false });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('ComplianceView', () => {
  it('renders report rows with title, asset, status and control pass/fail/skip counts', () => {
    mockReportsPage();
    renderWithProviders(<ComplianceView />);

    expect(screen.getByText('CIS Docker Benchmark')).toBeInTheDocument();
    expect(screen.getByText('CIS Kubernetes Benchmark')).toBeInTheDocument();

    expect(screen.getByText('acme/api:1.4.2')).toBeInTheDocument();
    expect(screen.getByText('db-01.internal')).toBeInTheDocument();

    expect(screen.getByText('32 pass · 8 fail · 4 skip')).toBeInTheDocument();
    expect(screen.getByText('10 pass · 20 fail · 0 skip')).toBeInTheDocument();

    // headline actionable count
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('shows an empty state when there are no compliance reports yet', () => {
    mockReportsPage({ data: page([]) });
    renderWithProviders(<ComplianceView />);

    expect(screen.getByText(/No compliance reports yet/)).toBeInTheDocument();
  });

  it('queues a re-scan for a report and shows a confirmation toast', async () => {
    mockReportsPage();
    rescanMutateAsync.mockResolvedValue(job());
    renderWithProviders(<ComplianceView />);

    await userEvent.click(screen.getByRole('button', { name: 'Re-scan CIS Docker Benchmark' }));

    await waitFor(() => {
      expect(rescanMutateAsync).toHaveBeenCalledWith('report-1');
    });
    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('CIS Docker Benchmark'));
    });
  });

  it('toasts an error when queueing a re-scan fails', async () => {
    mockReportsPage();
    rescanMutateAsync.mockRejectedValue(new Error('boom'));
    renderWithProviders(<ComplianceView />);

    await userEvent.click(screen.getByRole('button', { name: 'Re-scan CIS Kubernetes Benchmark' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith(expect.stringContaining('CIS Kubernetes Benchmark'));
    });
  });
});
