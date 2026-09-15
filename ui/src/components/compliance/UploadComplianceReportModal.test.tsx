import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { Job, JobStatus } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const toastInfo = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();
vi.mock('sonner', () => ({
  toast: {
    info: (...a: unknown[]) => toastInfo(...a),
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}));

import { UploadComplianceReportModal } from './UploadComplianceReportModal';

function job(status: JobStatus, overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    type: 'COMPLIANCE_SCAN',
    status,
    createdAt: '2026-09-11T12:00:00',
    itemsProcessed: 0,
    triggeredBy: 'jdesive@secy.test',
    ...overrides,
  };
}

/** Minimal stand-in for `Response`, matching what `api/client` actually reads. */
function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 202 ? 'Accepted' : 'OK',
    url: '',
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(body),
  };
}

const complianceFile = () =>
  new File(
    [
      JSON.stringify({
        ID: 'docker-cis-1.6.0',
        Title: 'CIS Docker Community Edition Benchmark',
        Version: '1.6.0',
        ArtifactName: 'acme/api:1.4.2',
        Results: [
          {
            id: '4',
            name: 'Container Images and Build File',
            results: [
              {
                Target: 'acme/api:1.4.2',
                misconfigurations: [
                  {
                    id: 'DS002',
                    avdId: 'AVD-DS-0002',
                    title: 'Image user should not be root',
                    status: 'FAIL',
                    resolution: 'Add a USER statement to the Dockerfile.',
                  },
                ],
              },
            ],
          },
        ],
      }),
    ],
    'cis-report.json',
    { type: 'application/json' },
  );

const imageScanFile = () =>
  new File(
    [
      JSON.stringify({
        SchemaVersion: 2,
        ArtifactName: 'acme/api:1.4.2',
        Results: [{ Target: 'acme/api:1.4.2 (alpine 3.19)', Vulnerabilities: [] }],
      }),
    ],
    'trivy-image.json',
    { type: 'application/json' },
  );

let polledJob: Job;
const fetchMock = vi.fn();

beforeEach(() => {
  polledJob = job('SUCCEEDED', { itemsProcessed: 44, message: 'Compliance report ingested' });
  fetchMock.mockImplementation((url: string) => {
    const href = String(url);
    if (href.includes('/api/products')) {
      return Promise.resolve(jsonResponse(200, []));
    }
    if (href.includes('/api/compliance/reports')) {
      return Promise.resolve(jsonResponse(202, job('QUEUED')));
    }
    if (href.includes('/api/jobs/')) {
      return Promise.resolve(jsonResponse(200, polledJob));
    }
    throw new Error(`unexpected request: ${href}`);
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

async function selectFile(file: File) {
  const input = document.getElementById('compliance-file') as HTMLInputElement;
  await userEvent.upload(input, file);
}

describe('UploadComplianceReportModal', () => {
  it('accepts a CIS-shaped report, pre-fills the asset name and posts to /compliance/reports', async () => {
    renderWithProviders(<UploadComplianceReportModal open onOpenChange={vi.fn()} />);

    await selectFile(complianceFile());

    expect(screen.getByText('cis-report.json')).toBeInTheDocument();
    expect(screen.getByLabelText('Asset name (optional)')).toHaveValue('acme/api:1.4.2');
    expect(screen.getByRole('button', { name: 'Upload report' })).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Upload report' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/compliance/reports'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('rejects a plain trivy image scan report', async () => {
    renderWithProviders(<UploadComplianceReportModal open onOpenChange={vi.fn()} />);

    await selectFile(imageScanFile());

    expect(screen.getByText(/does not look like a Trivy compliance report/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Upload report' })).toBeDisabled();
  });

  it('rejects a file that is not JSON at all', async () => {
    renderWithProviders(<UploadComplianceReportModal open onOpenChange={vi.fn()} />);

    await selectFile(new File(['not json'], 'nope.json'));

    expect(screen.getByText('That file is not valid JSON.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Upload report' })).toBeDisabled();
  });

  it('toasts success and closes the dialog once the job succeeds', async () => {
    const onOpenChange = vi.fn();
    renderWithProviders(<UploadComplianceReportModal open onOpenChange={onOpenChange} />);

    await selectFile(complianceFile());
    await userEvent.click(screen.getByRole('button', { name: 'Upload report' }));

    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith('Compliance report ingested and correlated.');
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('reports a failed upload and keeps the dialog open with the file still selected', async () => {
    polledJob = job('FAILED', { message: 'No asset name: could not determine what was audited' });
    const onOpenChange = vi.fn();
    renderWithProviders(<UploadComplianceReportModal open onOpenChange={onOpenChange} />);

    await selectFile(complianceFile());
    await userEvent.click(screen.getByRole('button', { name: 'Upload report' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith(
        'Compliance report upload failed. Check the file and the backend, then try again.',
      );
    });
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(screen.getByText('cis-report.json')).toBeInTheDocument();
  });
});
