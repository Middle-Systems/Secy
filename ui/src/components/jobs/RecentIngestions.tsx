import type { JobType } from '@/api/types';
import { useJobs } from '@/api/queries';
import { formatInteger, formatRelativeDate } from '@/lib/format';
import { isActiveJobStatus } from '@/lib/jobs';
import { cn } from '@/lib/utils';

import { JobStatusBadge } from './JobStatusBadge';

interface RecentIngestionsProps {
  /** Restrict to one feed. Omit for every feed. */
  type?: JobType;
  /** How many to show. Default 3. */
  limit?: number;
  className?: string;
}

/**
 * Compact history of the last few ingestion jobs, for dropping under a feed
 * view's ingest button. It is the only place a *previous* run's failure message
 * is visible — the toast for it is long gone by the time anyone looks.
 *
 * Polls while anything is still in flight, then goes quiet.
 */
export function RecentIngestions({ type, limit = 3, className }: RecentIngestionsProps) {
  const query = useJobs(
    { type, size: limit },
    {
      // Cheap liveness: keep refreshing the list while a run is going, stop once
      // everything has settled.
      refetchInterval: (q) =>
        q.state.data?.content.some((job) => isActiveJobStatus(job.status)) ? 5_000 : false,
    },
  );

  const jobs = query.data?.content ?? [];
  if (jobs.length === 0) return null;

  return (
    <section className={cn('rounded-lg border border-border', className)}>
      <h2 className="border-b border-border px-4 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Recent ingestions
      </h2>
      <ul className="divide-y divide-border">
        {jobs.map((job) => (
          <li key={job.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm">
            <JobStatusBadge status={job.status} />
            {!type && <span className="font-medium">{job.type}</span>}
            <span className="text-muted-foreground">
              {formatInteger(job.itemsProcessed)} records
            </span>
            <span className="text-muted-foreground">
              {formatRelativeDate(job.finishedAt ?? job.startedAt ?? job.createdAt)}
            </span>
            {job.message && (
              <span
                className={cn(
                  'w-full truncate text-xs sm:w-auto sm:flex-1',
                  job.status === 'FAILED' ? 'text-destructive' : 'text-muted-foreground',
                )}
                title={job.message}
              >
                {job.message}
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
