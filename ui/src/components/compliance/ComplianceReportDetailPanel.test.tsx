import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { ComplianceMisconfiguration, ComplianceReportDetail, Job, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useComplianceReportDetail = vi.fn();
const useComplianceMisconfigurations = vi.fn();
const rescanMutateAsync = vi.fn();
const useRescanComplianceReport = vi.fn();
const useJob = vi.fn();
const useActionableDetail = vi.fn();

vi.mock('@/api/queries', () => ({
  useComplianceReportDetail: (...args: unknown[]) => useComplianceReportDetail(...args),
  useComplianceMisconfigurations: (...args: unknown[]) => useComplianceMisconfigurations(...args),
  useRescanComplianceReport: (...args: unknown[]) => useRescanComplianceReport(...args),
  useJob: (...args: unknown[]) => useJob(...args),
  // ComplianceReportDetailPanel nests ActionableDetailPanel for its actionable-items list.
  useActionableDetail: (...args: unknown[]) => useActionableDetail(...args),
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

import { ComplianceReportDetailPanel } from './ComplianceReportDetailPanel';

function detail(overrides: Partial<ComplianceReportDetail> = {}): ComplianceReportDetail {
  return {
    id: 'report-1',
    benchmarkId: 'docker-cis-1.6.0',
    title: 'CIS Docker Benchmark',
    description: 'Docker Engine benchmark audit.',
    version: '1.6.0',
    assetId: 'asset-1',
    assetName: 'acme/api:1.4.2',
    status: 'COMPLETED',
    passedControls: 32,
    failedControls: 8,
    skippedControls: 4,
    totalControls: 44,
    scannedAt: '2026-09-10T12:00:00',
    createdAt: '2026-09-01T00:00:00',
    relatedResources: [],
    controls: [],
    misconfigurations: emptyPage([]),
    actionableItems: emptyPage([]),
    ...overrides,
  };
}

function emptyPage<T>(content: T[]): Page<T> {
  return {
    content,
    totalElements: content.length,
    totalPages: 1,
    number: 0,
    size: 10,
    numberOfElements: content.length,
    first: true,
    last: true,
    empty: content.length === 0,
  };
}

function misconfig(
  overrides: Partial<ComplianceMisconfiguration> = {},
): ComplianceMisconfiguration {
  return {
    id: 'misconfig-1',
    controlId: '4.1',
    controlName: 'Ensure a user for the container has been created',
    checkId: 'DS002',
    avdId: 'AVD-DS-0002',
    type: 'Dockerfile',
    title: 'Image user should not be root',
    description: 'Running containers as root increases the impact of a container escape.',
    message: null,
    resolution: 'Add a USER statement to the Dockerfile with a non-root user.',
    severity: 'HIGH',
    status: 'FAIL',
    target: 'Dockerfile',
    primaryUrl: 'https://avd.aquasec.com/misconfig/ds002',
    references: [],
    ...overrides,
  };
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
  useJob.mockReturnValue({ data: undefined });
  useActionableDetail.mockReturnValue({ data: undefined, isPending: false, isError: false });
  rescanMutateAsync.mockReset();
  useRescanComplianceReport.mockReturnValue({ mutateAsync: rescanMutateAsync, isPending: false });
  useComplianceMisconfigurations.mockReturnValue({
    data: emptyPage([misconfig()]),
    isFetching: false,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('ComplianceReportDetailPanel', () => {
  it('shows the control pass/fail/skip breakdown', () => {
    useComplianceReportDetail.mockReturnValue({ data: detail(), isPending: false, isError: false });
    renderWithProviders(<ComplianceReportDetailPanel id="report-1" onOpenChange={vi.fn()} />);

    expect(screen.getByText('32')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('passed')).toBeInTheDocument();
    expect(screen.getByText('failed')).toBeInTheDocument();
    expect(screen.getByText('skipped')).toBeInTheDocument();
  });

  it('shows the misconfiguration remediation text', () => {
    useComplianceReportDetail.mockReturnValue({ data: detail(), isPending: false, isError: false });
    renderWithProviders(<ComplianceReportDetailPanel id="report-1" onOpenChange={vi.fn()} />);

    expect(screen.getByText('Image user should not be root')).toBeInTheDocument();
    expect(screen.getByText('Remediation')).toBeInTheDocument();
    expect(
      screen.getByText('Add a USER statement to the Dockerfile with a non-root user.'),
    ).toBeInTheDocument();
  });

  it('triggers a re-scan against the right report id', async () => {
    useComplianceReportDetail.mockReturnValue({ data: detail(), isPending: false, isError: false });
    rescanMutateAsync.mockResolvedValue(job());
    renderWithProviders(<ComplianceReportDetailPanel id="report-1" onOpenChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: /Re-scan/ }));

    await waitFor(() => {
      expect(rescanMutateAsync).toHaveBeenCalledWith('report-1');
    });
  });

  it('shows a loading state while the report is pending', () => {
    useComplianceReportDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ComplianceReportDetailPanel id="report-1" onOpenChange={vi.fn()} />);

    expect(screen.getByText('Loading report…')).toBeInTheDocument();
  });
});
