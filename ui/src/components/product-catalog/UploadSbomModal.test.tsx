import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { Job, JobStatus } from '@/api/types';
import { renderWithProviders } from '@/test/render';

import type { DerivedProduct } from './product.types';

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

import { UploadSbomModal } from './UploadSbomModal';

const PRODUCT: DerivedProduct = {
  id: 'product-1',
  name: 'acme-web',
  description: '',
  createdAt: '2026-09-01T00:00:00',
  sboms: [],
  activeSbomStatusDisplay: 'Unknown',
  vulnerabilityCount: 0,
  actionableCount: 0,
};

function job(status: JobStatus, overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    type: 'SBOM_UPLOAD',
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

const cycloneDxFile = () =>
  new File(
    [JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, components: [] })],
    'cyclonedx.json',
    { type: 'application/json' },
  );

const spdxFile = () =>
  new File(
    [
      JSON.stringify({
        spdxVersion: 'SPDX-2.3',
        SPDXID: 'SPDXRef-DOCUMENT',
        packages: [],
      }),
    ],
    'spdx.json',
    { type: 'application/json' },
  );

/** What `GET /api/jobs/job-1` answers next. */
let polledJob: Job;
const fetchMock = vi.fn();

beforeEach(() => {
  polledJob = job('SUCCEEDED', {
    itemsProcessed: 3,
    message: 'CycloneDX SBOM components ingested',
  });
  fetchMock.mockImplementation((url: string) => {
    const href = String(url);
    if (href.includes('/api/sbom/') && href.includes('/sboms')) {
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
  const input = document.getElementById('sbom-file') as HTMLInputElement;
  await userEvent.upload(input, file);
}

describe('UploadSbomModal', () => {
  it('accepts an SPDX file client-side (not just CycloneDX)', async () => {
    renderWithProviders(<UploadSbomModal product={PRODUCT} onOpenChange={vi.fn()} />);

    await selectFile(spdxFile());

    expect(screen.getByText('spdx.json')).toBeInTheDocument();
    expect(screen.queryByText(/does not look like/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Analysis' })).toBeEnabled();
  });

  it('rejects a file that is neither CycloneDX nor SPDX', async () => {
    renderWithProviders(<UploadSbomModal product={PRODUCT} onOpenChange={vi.fn()} />);

    await selectFile(new File([JSON.stringify({ hello: 'world' })], 'nope.json'));

    expect(screen.getByText(/does not look like a CycloneDX or SPDX SBOM/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Analysis' })).toBeDisabled();
  });

  it('shows RUNNING progress with the live component count while the job is in flight', async () => {
    polledJob = job('RUNNING', { itemsProcessed: 2, message: 'Persisted 2 components' });
    renderWithProviders(<UploadSbomModal product={PRODUCT} onOpenChange={vi.fn()} />);

    await selectFile(cycloneDxFile());
    await userEvent.click(screen.getByRole('button', { name: 'Start Analysis' }));

    await waitFor(() => {
      expect(screen.getByText('Persisted 2 components')).toBeInTheDocument();
    });
    expect(screen.getByText('Running')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Processing…/ })).toBeDisabled();
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('toasts success and closes the dialog once the job succeeds', async () => {
    polledJob = job('SUCCEEDED', {
      itemsProcessed: 3,
      message: 'CycloneDX SBOM components ingested',
    });
    const onOpenChange = vi.fn();
    renderWithProviders(<UploadSbomModal product={PRODUCT} onOpenChange={onOpenChange} />);

    await selectFile(cycloneDxFile());
    await userEvent.click(screen.getByRole('button', { name: 'Start Analysis' }));

    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith('SBOM ingested and scanned.');
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('reports a failed job, keeps the dialog open, and lets the user retry without re-selecting the file', async () => {
    polledJob = job('FAILED', { message: 'Stashed SBOM body failed to re-parse as JSON' });
    const onOpenChange = vi.fn();
    renderWithProviders(<UploadSbomModal product={PRODUCT} onOpenChange={onOpenChange} />);

    await selectFile(cycloneDxFile());
    await userEvent.click(screen.getByRole('button', { name: 'Start Analysis' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith(
        'SBOM upload failed. Check the file and the backend, then try again.',
      );
    });
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    // The file is still selected — the retry button is live again, no re-pick needed.
    expect(screen.getByText('cyclonedx.json')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Start Analysis' })).toBeEnabled();
    });

    // Retry re-posts without touching the file input again.
    fetchMock.mockClear();
    polledJob = job('SUCCEEDED', { itemsProcessed: 3 });
    await userEvent.click(screen.getByRole('button', { name: 'Start Analysis' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/sbom/product-1/sboms'),
        expect.anything(),
      );
    });
  });
});
