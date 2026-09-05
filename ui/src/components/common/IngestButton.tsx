import { useState } from 'react';
import { DownloadCloud, Loader2, type LucideIcon } from 'lucide-react';
import { toast } from 'sonner';

import { Button, type ButtonProps } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface IngestButtonProps {
  /**
   * Kicks off the ingest. Pass a mutation's `mutateAsync` (or any promise
   * factory) — `useIngestKev()` → `ingest={() => kev.mutateAsync()}`.
   */
  ingest: () => Promise<unknown>;
  /** Idle label. Default "Ingest". */
  label?: string;
  /** Label while running. Default "Ingesting…". */
  pendingLabel?: string;
  /** `toast.info` fired on click. Pass `null` to skip. */
  startMessage?: string | null;
  /** `toast.success` fired on resolve. Pass `null` to skip. */
  successMessage?: string | null;
  /** `toast.error` fired on reject. Pass `null` to skip. */
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
 * Ingest-action button with the toast lifecycle every feed view shares:
 * `toast.info` on start, `toast.success` / `toast.error` on settle, spinner
 * while pending. Owns its own pending state.
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
  const [pending, setPending] = useState(false);

  const run = async () => {
    if (pending) return;
    setPending(true);
    if (startMessage) toast.info(startMessage);
    try {
      await ingest();
      if (successMessage) toast.success(successMessage);
      onIngested?.();
    } catch {
      if (errorMessage) toast.error(errorMessage);
    } finally {
      setPending(false);
    }
  };

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      disabled={disabled || pending}
      onClick={run}
      className={cn(className)}
    >
      {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
      {pending ? pendingLabel : label}
    </Button>
  );
}
