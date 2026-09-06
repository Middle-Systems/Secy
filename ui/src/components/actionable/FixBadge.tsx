import { CheckCircle2, CircleHelp, CircleSlash } from 'lucide-react';

import type { FixState } from '@/api/types';
import { cn } from '@/lib/utils';

interface FixBadgeProps {
  state: FixState;
  /** Shown as the badge text when `state` is `FIXED`, e.g. "2.17.1". */
  fixedVersions?: string | null;
  className?: string;
}

const BASE =
  'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold';

/**
 * Fix-availability pill: `FIXED` → green with the fixed version(s), `NO_FIX` →
 * grey "none yet", `UNKNOWN` → muted "unknown".
 */
export function FixBadge({ state, fixedVersions, className }: FixBadgeProps) {
  if (state === 'FIXED') {
    return (
      <span
        className={cn(BASE, 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400', className)}
      >
        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
        {fixedVersions?.trim() || 'Fixed'}
      </span>
    );
  }

  if (state === 'NO_FIX') {
    return (
      <span className={cn(BASE, 'bg-muted text-muted-foreground', className)}>
        <CircleSlash className="h-3.5 w-3.5" aria-hidden="true" />
        none yet
      </span>
    );
  }

  return (
    <span className={cn(BASE, 'font-medium text-muted-foreground', className)}>
      <CircleHelp className="h-3.5 w-3.5" aria-hidden="true" />
      unknown
    </span>
  );
}
