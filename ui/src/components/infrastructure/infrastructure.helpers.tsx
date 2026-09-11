/**
 * Small presentational pieces shared by the Infrastructure list, its detail
 * panel and the scan modal — the asset-inventory analogues of
 * `actionable/actionable.helpers.ts` and its badge components.
 */
import { CheckCircle2, Clock, Loader2, Server, XCircle, type LucideIcon } from 'lucide-react';

import type { AssetScanner, AssetStatus, AssetType } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

import { ASSET_TYPE_STYLES } from './asset-type';

/** Icon for an asset's `type` — container / host / service, per the roadmap's three kinds. */
export function AssetTypeIcon({ type, className }: { type: AssetType; className?: string }) {
  const Icon = ASSET_TYPE_STYLES[type]?.icon ?? Server;
  return <Icon className={cn('h-4 w-4 shrink-0', className)} aria-hidden="true" />;
}

interface StatusStyle {
  label: string;
  icon: LucideIcon;
  spin?: boolean;
  className: string;
}

/**
 * `asset.status` badge. Reuses `JobStatusBadge`'s visual language (same icon
 * family, only `PROCESSING` spins) even though the enum itself is distinct
 * from `JobStatus` (`PROCESSING`/`COMPLETED` vs. `RUNNING`/`SUCCEEDED`) —
 * a scan job and the asset it produces are two different lifecycles that
 * happen to track each other.
 */
const STATUS_STYLES: Record<AssetStatus, StatusStyle> = {
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

export function AssetStatusBadge({
  status,
  className,
}: {
  status: AssetStatus | null;
  className?: string;
}) {
  if (!status) {
    return (
      <Badge variant="outline" className={cn('gap-1 font-medium text-muted-foreground', className)}>
        Not scanned
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

/** `asset.scanner` badge — a plain, quiet label; there is no "better" scanner to color-code. */
export function AssetScannerBadge({
  scanner,
  className,
}: {
  scanner: AssetScanner | null;
  className?: string;
}) {
  if (!scanner) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Badge variant="outline" className={cn('font-medium text-muted-foreground', className)}>
      {scanner}
    </Badge>
  );
}
