import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';

import { useJob } from '@/api/queries';
import type { Job, JobStatus } from '@/api/types';
import { isTerminalJobStatus } from '@/lib/jobs';

export interface UseIngestJobOptions {
  /**
   * Queues the ingest — a mutation's `mutateAsync`. Must resolve with the `Job`
   * the backend answered 202 with.
   */
  ingest: () => Promise<Job>;
  /** `toast.info` fired on start. Pass `null` to skip. */
  startMessage?: string | null;
  /** `toast.success` fired when the job succeeds. Pass `null` to skip. */
  successMessage?: string | null;
  /** `toast.error` fired when the job fails. Pass `null` to skip. */
  errorMessage?: string | null;
  /** Runs once, after a successful ingest. */
  onIngested?: () => void;
}

export interface IngestJobState {
  /** Kick the ingest off. A no-op while one is already in flight. */
  start: () => Promise<void>;
  /** True from the click until the job reaches a terminal status. */
  running: boolean;
  /** True only between the click and the 202 landing. */
  enqueuing: boolean;
  /** Live status of the job being polled, if any. */
  status: JobStatus | undefined;
  /** Live record count off the job row. */
  itemsProcessed: number;
  jobId: string | undefined;
}

/**
 * The enqueue → poll → settle lifecycle every ingest control shares.
 *
 * Ingests are background jobs: the click `POST`s, the backend answers 202 with
 * a `Job`, and this polls it until it reaches a terminal status — so the toasts
 * fire when the ingest actually finishes rather than when the request returns.
 *
 * Shared by {@link IngestButton} and the CVE view's `IngestModal`, which differ
 * only in what they render.
 */
export function useIngestJob({
  ingest,
  startMessage,
  successMessage,
  errorMessage,
  onIngested,
}: UseIngestJobOptions): IngestJobState {
  const [enqueuing, setEnqueuing] = useState(false);
  const [jobId, setJobId] = useState<string | undefined>(undefined);

  const job = useJob(jobId);
  const status = job.data?.status;

  // Report each job once — the poll keeps returning the terminal row afterwards.
  const reported = useRef<string | null>(null);

  useEffect(() => {
    if (!jobId || !isTerminalJobStatus(status)) return;
    if (reported.current === jobId) return;
    reported.current = jobId;

    if (status === 'SUCCEEDED') {
      if (successMessage) toast.success(successMessage);
      onIngested?.();
    } else if (errorMessage) {
      // A CANCELLED job is a stopped run, not a broken feed — say so.
      toast.error(status === 'CANCELLED' ? 'Ingestion was cancelled.' : errorMessage);
    }

    // Stop polling. The job row stays cached for the history list.
    setJobId(undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, status]);

  const running = enqueuing || jobId !== undefined;

  const start = async () => {
    if (running) return;
    setEnqueuing(true);
    if (startMessage) toast.info(startMessage);
    try {
      const queued = await ingest();
      // When this feed was already in flight the backend hands back that job,
      // so the control picks up an ingest someone else started.
      if (queued?.id) {
        setJobId(queued.id);
      } else {
        // Nothing to poll (an older backend, or a stubbed test) — treat the
        // resolved promise as the whole story.
        if (successMessage) toast.success(successMessage);
        onIngested?.();
      }
    } catch {
      if (errorMessage) toast.error(errorMessage);
    } finally {
      setEnqueuing(false);
    }
  };

  return {
    start,
    running,
    enqueuing,
    status,
    itemsProcessed: job.data?.itemsProcessed ?? 0,
    jobId,
  };
}
