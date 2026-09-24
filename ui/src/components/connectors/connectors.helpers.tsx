/**
 * Small presentational pieces shared by the Connectors list and its row-level
 * sync control — the connector analogues of `infrastructure/infrastructure.helpers.tsx`.
 */
import {
  CheckCircle2,
  Clock,
  Cloud,
  CloudCog,
  Github,
  Loader2,
  RefreshCw,
  XCircle,
  type LucideIcon,
} from 'lucide-react';

import { useSyncConnector } from '@/api/queries';
import type { SourceConnector, SourceConnectorStatus, SourceConnectorType } from '@/api/types';
import { useIngestJob } from '@/components/jobs/useIngestJob';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

/** Display label for a connector's `type`, shared by the icon and the Type column. */
export const CONNECTOR_TYPE_LABELS: Record<SourceConnectorType, string> = {
  GITHUB: 'GitHub',
  AWS: 'AWS',
  AZURE: 'Azure',
};

const CONNECTOR_TYPE_ICONS: Record<SourceConnectorType, LucideIcon> = {
  GITHUB: Github,
  AWS: Cloud,
  AZURE: CloudCog,
};

/** Icon for a connector's `type`. */
export function ConnectorTypeIcon({
  type,
  className,
}: {
  type: SourceConnectorType;
  className?: string;
}) {
  const Icon = CONNECTOR_TYPE_ICONS[type];
  return <Icon className={cn('h-4 w-4 shrink-0', className)} aria-hidden="true" />;
}

interface StatusStyle {
  label: string;
  icon: LucideIcon;
  spin?: boolean;
  className: string;
}

/**
 * `connector.status` badge. Reuses `AssetStatusBadge`'s visual language
 * (same icon family, only `PROCESSING` spins) — the two lifecycles happen to
 * share the exact same string values (`QUEUED`/`PROCESSING`/`COMPLETED`/`FAILED`).
 * `null` means the connector was created but has never synced.
 */
const STATUS_STYLES: Record<SourceConnectorStatus, StatusStyle> = {
  QUEUED: { label: 'Queued', icon: Clock, className: 'text-muted-foreground' },
  PROCESSING: {
    label: 'Processing',
    icon: Loader2,
    spin: true,
    className: 'text-muted-foreground',
  },
  COMPLETED: {
    label: 'Completed',
    icon: CheckCircle2,
    className: 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400',
  },
  FAILED: { label: 'Failed', icon: XCircle, className: '' },
};

export function ConnectorStatusBadge({
  status,
  className,
}: {
  status: SourceConnectorStatus | null;
  className?: string;
}) {
  if (!status) {
    return (
      <Badge variant="outline" className={cn('gap-1 font-medium text-muted-foreground', className)}>
        Never synced
      </Badge>
    );
  }

  const style = STATUS_STYLES[status];
  const variant = status === 'FAILED' ? 'destructive' : 'outline';
  return (
    <Badge variant={variant} className={cn('gap-1 font-medium', style.className, className)}>
      <style.icon className={cn('h-3 w-3', style.spin && 'animate-spin')} aria-hidden="true" />
      {style.label}
    </Badge>
  );
}

/**
 * The "Status" cell doubles as the "Sync now" control, since both need to
 * agree on whether a sync is in flight right now. Drives the same
 * `useIngestJob` enqueue -> poll -> settle lifecycle `ScanAssetModal` uses,
 * just inline on the row instead of behind a modal — there is no file to
 * pick for this action, just a button press. While a locally-triggered sync
 * is running this shows a live "Processing" badge even though the connector
 * row's own `status` field only catches up once the list re-fetches (which
 * `useJob`'s `FEED_KEYS` invalidation triggers on success).
 */
export function ConnectorSyncCell({ connector }: { connector: SourceConnector }) {
  const syncConnector = useSyncConnector();
  const { start, running } = useIngestJob({
    ingest: () => syncConnector.mutateAsync(connector.id),
    startMessage: `Syncing "${connector.name}"…`,
    successMessage: `"${connector.name}" synced.`,
    errorMessage: `Sync failed for "${connector.name}". Check the backend logs and try again.`,
  });

  return (
    <div className="flex items-center gap-2">
      <ConnectorStatusBadge status={running ? 'PROCESSING' : connector.status} />
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7 text-muted-foreground hover:text-foreground"
        title="Sync now"
        aria-label={`Sync ${connector.name} now`}
        disabled={running}
        onClick={(event) => {
          event.stopPropagation();
          void start();
        }}
      >
        {running ? (
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
        ) : (
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
        )}
      </Button>
    </div>
  );
}
