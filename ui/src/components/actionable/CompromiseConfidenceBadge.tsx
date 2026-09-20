import { ClockAlert, ShieldQuestion, ShieldX, type LucideIcon } from 'lucide-react';

import type { CompromiseConfidence } from '@/api/types';
import { cn } from '@/lib/utils';

interface Style {
  label: string;
  icon: LucideIcon;
  className: string;
}

const BASE =
  'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold';

/**
 * `compromiseConfidence` answers "how sure are we that you are compromised" —
 * a different axis than {@link MatchConfidence}, which answers "is this really
 * my component?" for a CVE correlation. `CONFIRMED` is the feed's own
 * statement with no inference (red — nothing to weigh up); `LIKELY` needed an
 * inference (amber, same cautionary weight `MatchConfidenceBadge` gives
 * `HEURISTIC`); `INVESTIGATE` is IOC aging's decayed state — muted, since the
 * finding is demoted rather than dismissed. Pair with the finding's `agedAt`
 * where it's non-null; that's what explains *why* it only reads INVESTIGATE.
 */
const STYLES: Record<CompromiseConfidence, Style> = {
  CONFIRMED: {
    label: 'Confirmed',
    icon: ShieldX,
    className: 'bg-destructive/10 text-destructive',
  },
  LIKELY: {
    label: 'Likely',
    icon: ShieldQuestion,
    className: 'bg-severity-medium/10 text-severity-medium',
  },
  INVESTIGATE: {
    label: 'Investigate',
    icon: ClockAlert,
    className: 'bg-muted text-muted-foreground',
  },
};

export function CompromiseConfidenceBadge({
  confidence,
  className,
}: {
  confidence: CompromiseConfidence;
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
