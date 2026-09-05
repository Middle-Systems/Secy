import { DownloadCloud, Loader2, type LucideIcon } from 'lucide-react';

import type { Job } from '@/api/types';
import { useIngestJob } from '@/components/jobs/useIngestJob';
import { Button, type ButtonProps } from '@/components/ui/button';
import { formatInteger } from '@/lib/format';
import { cn } from '@/lib/utils';

interface IngestButtonProps {
  /**
   * Queues the ingest. Pass a mutation's `mutateAsync` —
   * `useIngestKev()` → `ingest={() => kev.mutateAsync()}`. It must resolve with
   * the `Job` the backend answered 202 with; the button takes over from there.
   */
  ingest: () => Promise<Job>;
  /** Idle label. Default "Ingest". */
  label?: string;
  /** Label while the job is running. Default "Ingesting…". */
  pendingLabel?: string;
  /** Label between the click and a worker picking the job up. Default "Queued…". */
  queuedLabel?: string;
  /** `toast.info` fired on click. Pass `null` to skip. */
  startMessage?: string | null;
  /** `toast.success` fired when the job succeeds. Pass `null` to skip. */
  successMessage?: string | null;
  /** `toast.error` fired when the job fails. Pass `null` to skip. */
  errorMessage?: string | null;
  /** Leading icon. Default `DownloadCloud`; swapped for a spinner while pending. */
  icon?: LucideIcon;
  /** Also disable the button (e.g. while the table is loading). */
  disabled?: boolean;
  variant?: ButtonProps['variant'];
  size?: ButtonProps['size'];
  className?: string;
  /** Extra work after a successful ingest (e.g. reset to page 0). */
  onIngested?: () => void;
}

/**
 * Ingest-action button for the feed views.
 *
 * Ingests are background jobs now: the click `POST`s, the backend answers 202
 * with a `Job`, and {@link useIngestJob} polls it until it settles. The label
 * tracks that — "Queued…", then "Ingesting… (12,480)" with the live record
 * count, then back to idle — and the toasts fire when the job actually
 * finishes rather than when the request returns.
 *
 * The prop surface is unchanged apart from `ingest` now resolving with a `Job`
 * instead of `unknown`, which the `useIngest*` hooks already do.
 *
 * @example
 * const ingest = useIngestKev();
 * <IngestButton
 *   ingest={() => ingest.mutateAsync()}
 *   label="Ingest Latest KEV"
 *   startMessage="Starting CISA KEV ingestion…"
 *   successMessage="Successfully synced with CISA"
 *   errorMessage="CISA API might be unreachable"
 *   onIngested={() => setPage(0)}
 * />
 */
export function IngestButton({
  ingest,
  label = 'Ingest',
  pendingLabel = 'Ingesting…',
  queuedLabel = 'Queued…',
  startMessage,
  successMessage = 'Ingestion complete.',
  errorMessage = 'Ingestion failed.',
  icon: Icon = DownloadCloud,
  disabled = false,
  variant = 'default',
  size = 'default',
  className,
  onIngested,
}: IngestButtonProps) {
  const { start, running, enqueuing, status, itemsProcessed } = useIngestJob({
    ingest,
    startMessage,
    successMessage,
    errorMessage,
    onIngested,
  });

  const buttonLabel = (() => {
    if (enqueuing || status === 'QUEUED') return queuedLabel;
    if (!running) return label;
    return itemsProcessed > 0
      ? `${pendingLabel} (${formatInteger(itemsProcessed)})`
      : pendingLabel;
  })();

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      disabled={disabled || running}
      onClick={start}
      className={cn(className)}
    >
      {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
      {buttonLabel}
    </Button>
  );
}
