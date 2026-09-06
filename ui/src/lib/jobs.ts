import type { JobStatus } from '@/api/types';

/**
 * Job statuses a job never leaves. Mirrors `JobStatus.isTerminal()` on the
 * backend — the poll in `useJob` stops here, and so does the ingest button's
 * spinner.
 */
export const TERMINAL_JOB_STATUSES = ['SUCCEEDED', 'FAILED', 'CANCELLED'] as const;

export function isTerminalJobStatus(status: JobStatus | undefined): boolean {
  return status !== undefined && (TERMINAL_JOB_STATUSES as readonly string[]).includes(status);
}

/** True while the job still holds its feed's single active slot. */
export function isActiveJobStatus(status: JobStatus | undefined): boolean {
  return status !== undefined && !isTerminalJobStatus(status);
}

/** Short label for a status, for badges and button text. */
export const JOB_STATUS_LABELS: Record<JobStatus, string> = {
  QUEUED: 'Queued',
  RUNNING: 'Running',
  SUCCEEDED: 'Succeeded',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
};
