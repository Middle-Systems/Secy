/**
 * Small presentational pieces shared by the Compliance list, its detail panel
 * and the upload modal — the compliance analogues of
 * `infrastructure/infrastructure.helpers.tsx` and its badge components.
 */
import { CheckCircle2, Clock, Loader2, MinusCircle, XCircle, type LucideIcon } from 'lucide-react';

import type { ComplianceReportStatus, ComplianceStatus } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { formatInteger } from '@/lib/format';
import { cn } from '@/lib/utils';

interface StatusStyle {
  label: string;
  icon: LucideIcon;
  spin?: boolean;
  className: string;
}

/**
 * `report.status` badge — the ingest/correlation lifecycle, not the benchmark
 * verdict. Reuses `AssetStatusBadge`'s visual language (same icon family, only
 * `PROCESSING` spins), since a compliance report and an asset scan track the
 * same kind of job.
 */
const REPORT_STATUS_STYLES: Record<ComplianceReportStatus, StatusStyle> = {
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

export function ComplianceReportStatusBadge({
  status,
  className,
}: {
  status: ComplianceReportStatus | null | undefined;
  className?: string;
}) {
  const style = status ? REPORT_STATUS_STYLES[status] : undefined;
  if (!style) {
    return (
      <Badge variant="outline" className={cn('gap-1 font-medium text-muted-foreground', className)}>
        Unknown
      </Badge>
    );
  }
  const variant = status === 'FAILED' ? 'destructive' : 'outline';
  return (
    <Badge variant={variant} className={cn('gap-1 font-medium', style.className, className)}>
      <style.icon className={cn('h-3 w-3', style.spin && 'animate-spin')} aria-hidden="true" />
      {style.label}
    </Badge>
  );
}

/** `misconfiguration.status` / `control.status` badge — the benchmark's own PASS/FAIL/SKIP verdict. */
const CHECK_STATUS_STYLES: Record<ComplianceStatus, StatusStyle> = {
  PASS: {
    label: 'Pass',
    icon: CheckCircle2,
    className: 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400',
  },
  FAIL: { label: 'Fail', icon: XCircle, className: '' },
  SKIP: { label: 'Skip', icon: MinusCircle, className: 'text-muted-foreground' },
};

export function ComplianceCheckStatusBadge({
  status,
  className,
}: {
  status: ComplianceStatus;
  className?: string;
}) {
  const style = CHECK_STATUS_STYLES[status];
  const variant = status === 'FAIL' ? 'destructive' : 'outline';
  return (
    <Badge variant={variant} className={cn('gap-1 font-medium', style.className, className)}>
      <style.icon className="h-3 w-3" aria-hidden="true" />
      {style.label}
    </Badge>
  );
}

export interface ControlCounts {
  passedControls: number;
  failedControls: number;
  skippedControls: number;
  totalControls: number;
}

/**
 * Compact pass/fail/skip breakdown — a 3-segment stacked bar (failed first,
 * since that's what a reader scans for). Used in the report list table; the
 * detail panel pairs this with {@link ControlBreakdownCounts} for the numbers.
 */
export function ControlBreakdownBar({
  passedControls,
  failedControls,
  skippedControls,
  totalControls,
  className,
}: ControlCounts & { className?: string }) {
  if (totalControls <= 0) {
    return <span className="text-xs text-muted-foreground">No controls evaluated</span>;
  }
  const pct = (n: number) => `${(n / totalControls) * 100}%`;
  return (
    <div
      className={cn(
        'flex h-2 w-full min-w-[80px] overflow-hidden rounded-full bg-muted',
        className,
      )}
      role="img"
      aria-label={`${formatInteger(passedControls)} passed, ${formatInteger(failedControls)} failed, ${formatInteger(skippedControls)} skipped`}
    >
      {failedControls > 0 && (
        <div className="h-full bg-destructive" style={{ width: pct(failedControls) }} />
      )}
      {passedControls > 0 && (
        <div className="h-full bg-emerald-500" style={{ width: pct(passedControls) }} />
      )}
      {skippedControls > 0 && (
        <div className="h-full bg-muted-foreground/40" style={{ width: pct(skippedControls) }} />
      )}
    </div>
  );
}

/** The numeric legend for {@link ControlBreakdownBar} — three small counts with icons. */
export function ControlBreakdownCounts({
  passedControls,
  failedControls,
  skippedControls,
}: ControlCounts) {
  return (
    <div className="flex items-center gap-4 text-sm">
      <span className="flex items-center gap-1.5 font-semibold text-emerald-600 dark:text-emerald-400">
        <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
        {formatInteger(passedControls)}
        <span className="font-normal text-muted-foreground">passed</span>
      </span>
      <span className="flex items-center gap-1.5 font-semibold text-destructive">
        <XCircle className="h-4 w-4" aria-hidden="true" />
        {formatInteger(failedControls)}
        <span className="font-normal text-muted-foreground">failed</span>
      </span>
      <span className="flex items-center gap-1.5 font-semibold text-muted-foreground">
        <MinusCircle className="h-4 w-4" aria-hidden="true" />
        {formatInteger(skippedControls)}
        <span className="font-normal">skipped</span>
      </span>
    </div>
  );
}
