import { CheckCircle2, CircleHelp, CircleSlash } from 'lucide-react';

import type { FixSource, FixState } from '@/api/types';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

interface FixBadgeProps {
  state: FixState;
  /** Shown as the badge text when `state` is `FIXED`, e.g. "2.17.1". */
  fixedVersions?: string | null;
  /**
   * Where the fixed version came from. `CPE_RANGE` always means the version
   * is inferred from a version-range boundary rather than stated by a vendor
   * or scanner, so it's always shown as approximate — regardless of
   * `matchConfidence` — via a `~` prefix and an explanatory tooltip. This is
   * the "the pair that most needs a visual caveat" case per the Phase 2
   * contract when it also coincides with `matchConfidence: HEURISTIC`.
   */
  fixSource?: FixSource | null;
  className?: string;
}

const BASE =
  'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold';

const APPROXIMATE_EXPLANATION =
  'Approximate — derived from a version-range boundary, not a vendor statement.';

/**
 * Fix-availability pill: `FIXED` → green with the fixed version(s), `NO_FIX` →
 * grey "none yet", `UNKNOWN` → muted "unknown".
 */
export function FixBadge({ state, fixedVersions, fixSource, className }: FixBadgeProps) {
  if (state === 'FIXED') {
    const label = fixedVersions?.trim() || 'Fixed';
    const approximate = fixSource === 'CPE_RANGE';
    const pill = (
      <span
        className={cn(
          BASE,
          'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
          approximate && 'cursor-help',
          className,
        )}
      >
        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
        {approximate ? `~${label}` : label}
      </span>
    );

    if (!approximate) return pill;

    return (
      <Tooltip>
        <TooltipTrigger asChild>{pill}</TooltipTrigger>
        <TooltipContent>{APPROXIMATE_EXPLANATION}</TooltipContent>
      </Tooltip>
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
