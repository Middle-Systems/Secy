import { CircleCheck, GitBranch, Wand2, type LucideIcon } from 'lucide-react';

import type { MatchConfidence } from '@/api/types';
import { cn } from '@/lib/utils';

interface Style {
  label: string;
  icon: LucideIcon;
  className: string;
}

const BASE =
  'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold';

/**
 * `matchConfidence` answers a different question than `FixSource`: "is this
 * really my component?" rather than "how good is this fix version?". `EXACT`
 * and `RANGE` are both normal, trustworthy outcomes, so they read as quiet
 * muted text — no color is spent implying they're "good". `HEURISTIC` (a
 * name-guess correlation) gets a distinct amber cautionary treatment,
 * deliberately not the red `ExploitBadge` uses for `IN_THE_WILD`.
 */
const STYLES: Record<MatchConfidence, Style> = {
  EXACT: {
    label: 'Exact match',
    icon: CircleCheck,
    className: 'font-medium text-muted-foreground',
  },
  RANGE: {
    label: 'Range match',
    icon: GitBranch,
    className: 'font-medium text-muted-foreground',
  },
  HEURISTIC: {
    label: 'Heuristic match',
    icon: Wand2,
    className: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
  },
};

/** Small badge/indicator for `ActionableItem.matchConfidence` / `ActionableDetail.matchConfidence`. */
export function MatchConfidenceBadge({
  confidence,
  className,
}: {
  confidence: MatchConfidence;
  className?: string;
}) {
  const { label, icon: Icon, className: styleClassName } = STYLES[confidence];
  return (
    <span className={cn(BASE, styleClassName, className)}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {label}
    </span>
  );
}
