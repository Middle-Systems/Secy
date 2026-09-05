import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

/** Left-accent colour for a {@link StatCard}. Maps to design tokens, not hex. */
export type StatCardAccent = 'blue' | 'red' | 'amber' | 'cyan';

const ACCENT: Record<StatCardAccent, { bar: string; chip: string }> = {
  blue: { bar: 'border-l-primary', chip: 'bg-primary/10 text-primary' },
  red: { bar: 'border-l-destructive', chip: 'bg-destructive/10 text-destructive' },
  amber: {
    bar: 'border-l-severity-medium',
    chip: 'bg-severity-medium/10 text-severity-medium',
  },
  cyan: { bar: 'border-l-severity-low', chip: 'bg-severity-low/10 text-severity-low' },
};

interface StatCardProps {
  /** Short uppercase caption, e.g. "Active Exploits (KEV)". */
  label: string;
  /** The headline figure — pre-formatted (thousands separators etc.). */
  value: ReactNode;
  icon: LucideIcon;
  accent?: StatCardAccent;
  className?: string;
}

/**
 * A KPI tile: tinted icon chip, caption, and a large value, with a coloured
 * left accent. Shared across dashboard-style views (KEV / EPSS / CVE / product
 * catalog) — keep it presentational, pass an already-formatted `value`.
 */
export function StatCard({ label, value, icon: Icon, accent = 'blue', className }: StatCardProps) {
  const styles = ACCENT[accent];
  return (
    <Card className={cn('border-l-4', styles.bar, className)}>
      <CardContent className="flex items-center gap-4 p-5">
        <span
          className={cn(
            'flex h-12 w-12 shrink-0 items-center justify-center rounded-lg',
            styles.chip,
          )}
        >
          <Icon className="h-6 w-6" aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="truncate text-xs font-bold uppercase tracking-wide text-muted-foreground">
            {label}
          </p>
          <p className="text-2xl font-bold text-foreground">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}
