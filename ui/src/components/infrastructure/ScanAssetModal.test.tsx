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

import { ScanAssetModal } from './ScanAssetModal';

function job(status: JobStatus, overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    type: 'ASSET_SCAN',
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

const trivyFile = () =>
  new File(
    [
      JSON.stringify({
        SchemaVersion: 2,
        ArtifactName: 'acme/api:1.4.2',
        Results: [{ Target: 'acme/api:1.4.2 (alpine 3.19)', Vulnerabilities: [] }],
      }),
    ],
    'trivy.json',
    { type: 'application/json' },
  );

const grypeFile = () =>
  new File(
    [
      JSON.stringify({
        matches: [],
        source: { target: { userInput: 'acme/api:1.4.2' } },
      }),
    ],
    'grype.json',
    { type: 'application/json' },
  );

let polledJob: Job;
const fetchMock = vi.fn();

beforeEach(() => {
  polledJob = job('SUCCEEDED', { itemsProcessed: 5, message: 'Trivy scan components ingested' });
  fetchMock.mockImplementation((url: string) => {
    const href = String(url);
    if (href.includes('/api/products')) {
      return Promise.resolve(jsonResponse(200, []));
    }
    if (href.includes('/api/assets/scan/trivy')) {
      return Promise.resolve(jsonResponse(202, job('QUEUED')));
    }
    if (href.includes('/api/assets/scan/grype')) {
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
  const input = document.getElementById('scan-file') as HTMLInputElement;
  await userEvent.upload(input, file);
}

describe('ScanAssetModal', () => {
  it('auto-detects Trivy from the report shape and posts to the trivy endpoint', async () => {
    renderWithProviders(<ScanAssetModal open onOpenChange={vi.fn()} />);

    await selectFile(trivyFile());

    expect(screen.getByText('trivy.json')).toBeInTheDocument();
    expect(screen.getByText('Auto-detected from the file.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Scan' })).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/assets/scan/trivy'),
        expect.anything(),
      );
    });
  });

  it('auto-detects Grype from the report shape and posts to the grype endpoint', async () => {
    renderWithProviders(<ScanAssetModal open onOpenChange={vi.fn()} />);

    await selectFile(grypeFile());

    expect(screen.getByText('grype.json')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Scan' })).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/assets/scan/grype'),
        expect.anything(),
      );
    });
  });

  it('rejects a file that looks like neither Trivy nor Grype', async () => {
    renderWithProviders(<ScanAssetModal open onOpenChange={vi.fn()} />);

    await selectFile(new File([JSON.stringify({ hello: 'world' })], 'nope.json'));

    expect(
      screen.getByText(/does not look like a Trivy or Grype JSON report/i),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Scan' })).toBeDisabled();
  });

  it('toasts success and closes the dialog once the job succeeds', async () => {
    const onOpenChange = vi.fn();
    renderWithProviders(<ScanAssetModal open onOpenChange={onOpenChange} />);

    await selectFile(trivyFile());
    await userEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith('Asset scanned and correlated.');
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('reports a failed scan and keeps the dialog open with the file still selected', async () => {
    polledJob = job('FAILED', { message: 'Not a recognized Trivy report' });
    const onOpenChange = vi.fn();
    renderWithProviders(<ScanAssetModal open onOpenChange={onOpenChange} />);

    await selectFile(trivyFile());
    await userEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith(
        'Asset scan failed. Check the file and the backend, then try again.',
      );
    });
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(screen.getByText('trivy.json')).toBeInTheDocument();
  });
});
