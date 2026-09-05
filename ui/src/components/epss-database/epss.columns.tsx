import type { ColumnDef } from '@tanstack/react-table';

import type { EPSS } from '@/api/types';
import { Progress } from '@/components/ui/progress';
import { formatDate, formatPercent } from '@/lib/format';
import { cn } from '@/lib/utils';

import { epssRisk, type EpssRiskLevel } from './epss.risk';

/** Text-only colour per bucket, for the probability figure next to the bar. */
const RISK_TEXT: Record<EpssRiskLevel, string> = {
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  elevated: 'text-severity-medium',
  low: 'text-severity-low',
};

/** Ordinal suffix for a whole number — 1 → "st", 2 → "nd", 94 → "th". */
function ordinal(n: number): string {
  const mod100 = n % 100;
  if (mod100 >= 11 && mod100 <= 13) return 'th';
  switch (n % 10) {
    case 1:
      return 'st';
    case 2:
      return 'nd';
    case 3:
      return 'rd';
    default:
      return 'th';
  }
}

/** Column defs for the EPSS table. Mirrors the Angular `epss-database` view. */
export function epssColumns(): ColumnDef<EPSS, unknown>[] {
  return [
    {
      accessorKey: 'cve',
      header: 'CVE',
      cell: ({ row }) => (
        <span className="font-mono text-sm font-semibold text-primary">{row.original.cve}</span>
      ),
    },
    {
      accessorKey: 'epss',
      header: 'Probability (EPSS)',
      size: 260,
      cell: ({ row }) => {
        const score = row.original.epss;
        const risk = epssRisk(score);
        const pct = Number.isFinite(score) ? Math.max(0, Math.min(100, score * 100)) : 0;
        return (
          <div className="flex min-w-[180px] items-center gap-2">
            <span className={cn('w-14 shrink-0 text-sm font-bold tabular-nums', RISK_TEXT[risk.level])}>
              {formatPercent(score, 2)}
            </span>
            <Progress
              value={pct}
              className={cn('h-1.5', risk.barClass)}
              aria-label={`Exploitation probability ${formatPercent(score, 2)}`}
            />
          </div>
        );
      },
    },
    {
      accessorKey: 'percentile',
      header: 'Percentile',
      cell: ({ row }) => {
        const p = row.original.percentile;
        const rank = Number.isFinite(p) ? Math.round(p * 100) : null;
        return (
          <div className="whitespace-nowrap">
            <div className="text-sm font-medium text-foreground">{formatPercent(p, 1)}</div>
            {rank !== null && (
              <div className="text-xs text-muted-foreground">
                {rank}
                {ordinal(rank)} pct
              </div>
            )}
          </div>
        );
      },
    },
    {
      id: 'risk',
      header: () => <span className="block text-center">Risk</span>,
      cell: ({ row }) => {
        const risk = epssRisk(row.original.epss);
        return (
          <div className="text-center">
            <span
              className={cn(
                'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold',
                risk.colorClass,
              )}
            >
              {risk.label}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: 'date',
      header: 'Date',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatDate(row.original.date)}
        </span>
      ),
    },
  ];
}
