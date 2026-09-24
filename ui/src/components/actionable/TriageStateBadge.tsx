import { CheckCircle2, CircleDot, Clock, Eye, XCircle, type LucideIcon } from 'lucide-react';

import type { TriageState } from '@/api/types';
import { cn } from '@/lib/utils';

import { TRIAGE_STATE_LABELS } from './actionable.helpers';

interface Style {
  icon: LucideIcon;
  className: string;
}

const STYLES: Record<TriageState, Style> = {
  OPEN: { icon: CircleDot, className: 'bg-muted text-muted-foreground' },
  ACKNOWLEDGED: { icon: Eye, className: 'bg-primary/10 text-primary' },
  SNOOZED: { icon: Clock, className: 'bg-severity-medium/10 text-severity-medium' },
  RESOLVED: { icon: CheckCircle2, className: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' },
  FALSE_POSITIVE: { icon: XCircle, className: 'text-muted-foreground border border-border bg-transparent' },
};

/** Person-driven triage state pill (Phase 7) — `TRIAGE_STATE_LABELS` badged distinctly per state. */
export function TriageStateBadge({ state, className }: { state: TriageState; className?: string }) {
  const { icon: Icon, className: styleClassName } = STYLES[state];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold',
        styleClassName,
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {TRIAGE_STATE_LABELS[state]}
    </span>
  );
}
