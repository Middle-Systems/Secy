import { CheckCircle2, CircleSlash, Clock, Loader2, XCircle, type LucideIcon } from 'lucide-react';

import type { JobStatus } from '@/api/types';
import { Badge, type BadgeProps } from '@/components/ui/badge';
import { JOB_STATUS_LABELS } from '@/lib/jobs';
import { cn } from '@/lib/utils';

interface StatusStyle {
  variant: BadgeProps['variant'];
  icon: LucideIcon;
  /** Only `RUNNING` spins — a static spinner reads as a hung UI. */
  spin?: boolean;
  className?: string;
}

const STYLES: Record<JobStatus, StatusStyle> = {
  QUEUED: { variant: 'outline', icon: Clock },
  RUNNING: { variant: 'secondary', icon: Loader2, spin: true },
  SUCCEEDED: {
    variant: 'outline',
    icon: CheckCircle2,
    className: 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400',
  },
  FAILED: { variant: 'destructive', icon: XCircle },
  CANCELLED: { variant: 'outline', icon: CircleSlash, className: 'text-muted-foreground' },
};

interface JobStatusBadgeProps {
  status: JobStatus;
  className?: string;
}

/** Status pill for an ingestion job — icon plus label, colour-coded by state. */
export function JobStatusBadge({ status, className }: JobStatusBadgeProps) {
  const { variant, icon: Icon, spin, className: statusClass } = STYLES[status];

  return (
    <Badge variant={variant} className={cn('gap-1 font-medium', statusClass, className)}>
      <Icon className={cn('h-3 w-3', spin && 'animate-spin')} aria-hidden="true" />
      {JOB_STATUS_LABELS[status]}
    </Badge>
  );
}
