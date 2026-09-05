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

import { IngestButton } from './IngestButton';

function job(status: JobStatus, overrides: Partial<Job> = {}): Job {
  return {
    id: 'job-1',
    type: 'KEV',
    status,
    createdAt: '2026-09-05T12:00:00',
    itemsProcessed: 0,
    triggeredBy: 'jdesive@secy.test',
    ...overrides,
  };
}

/** Minimal stand-in for `Response`, matching what `api/client` actually reads. */
function okJson(body: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    url: '',
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(body),
  };
}

/** What `GET /api/jobs/job-1` answers next. */
let polledJob: Job;
const fetchMock = vi.fn();

beforeEach(() => {
  polledJob = job('SUCCEEDED', { itemsProcessed: 4_200, message: '4200 KEV entries ingested' });
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes('/api/jobs/')) return Promise.resolve(okJson(polledJob));
    throw new Error(`unexpected request: ${String(url)}`);
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function renderButton(overrides: Partial<Parameters<typeof IngestButton>[0]> = {}) {
  const ingest = vi.fn().mockResolvedValue(job('QUEUED'));
  const onIngested = vi.fn();
  renderWithProviders(
    <IngestButton
      ingest={ingest}
      label="Ingest Latest KEV"
      startMessage="Starting CISA KEV ingestion…"
      successMessage="Successfully synced with CISA"
      errorMessage="CISA API might be unreachable"
      onIngested={onIngested}
      {...overrides}
    />,
  );
  return { ingest, onIngested };
}

describe('IngestButton', () => {
  it('queues the ingest, polls the job and reports success when it finishes', async () => {
    const { ingest, onIngested } = renderButton();

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    expect(ingest).toHaveBeenCalledTimes(1);
    expect(toastInfo).toHaveBeenCalledWith('Starting CISA KEV ingestion…');

    // The success toast fires when the *job* finishes, not when the POST returns.
    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith('Successfully synced with CISA');
    });
    expect(onIngested).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/jobs/job-1'),
      expect.anything(),
    );

    // Polling stopped and the button is usable again.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Ingest Latest KEV' })).toBeEnabled();
    });
  });

  it('shows the live record count while the job is running', async () => {
    polledJob = job('RUNNING', { itemsProcessed: 1_200, message: 'Ingested 1200 KEV entries…' });
    renderButton();

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Ingesting… \(1,200\)/ })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Ingesting…/ })).toBeDisabled();
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('reports a job that fails', async () => {
    polledJob = job('FAILED', { message: 'RestClientException: cisa.gov is unreachable' });
    const { onIngested } = renderButton();

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith('CISA API might be unreachable');
    });
    expect(onIngested).not.toHaveBeenCalled();
  });

  it('distinguishes a cancelled job from a broken feed', async () => {
    polledJob = job('CANCELLED', { message: 'Cancelled before completion.' });
    renderButton();

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith('Ingestion was cancelled.');
    });
  });

  it('reports a failure to even queue the ingest', async () => {
    const ingest = vi.fn().mockRejectedValue(new Error('502'));
    renderButton({ ingest });

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith('CISA API might be unreachable');
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Ingest Latest KEV' })).toBeEnabled();
  });

  it('picks up the job the backend hands back when an ingest is already in flight', async () => {
    // The backend answers 202 with the job already running rather than a new one.
    const ingest = vi.fn().mockResolvedValue(job('RUNNING', { itemsProcessed: 900 }));
    polledJob = job('RUNNING', { itemsProcessed: 900 });
    renderButton({ ingest });

    await userEvent.click(screen.getByRole('button', { name: 'Ingest Latest KEV' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Ingesting… \(900\)/ })).toBeInTheDocument();
    });
  });
});
