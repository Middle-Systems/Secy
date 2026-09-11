import type { ColumnDef } from '@tanstack/react-table';
import { ShieldAlert } from 'lucide-react';

import type { ActionableItem } from '@/api/types';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { formatPercent, formatPercentile, formatRelativeDate } from '@/lib/format';
import { cn } from '@/lib/utils';

import { componentLabel, isKevOverdue } from './actionable.helpers';
import { ExploitBadge } from './ExploitBadge';
import { FixBadge } from './FixBadge';
import { MatchConfidenceBadge } from './MatchConfidenceBadge';

const DASH = <span className="text-xs text-muted-foreground">—</span>;

/**
 * Column defs for the Actionable Items table. Non-sortable by design — the sort
 * is fixed server-side (EPSS desc); row clicks open the detail panel, wired in
 * the view via `DataTable`'s `onRowClick`.
 */
export function actionableColumns(): ColumnDef<ActionableItem, unknown>[] {
  return [
    {
      id: 'severity',
      header: 'Severity',
      cell: ({ row }) => (
        <SeverityBadge
          severity={row.original.baseSeverity}
          score={row.original.cvssScore ?? undefined}
        />
      ),
    },
    {
      accessorKey: 'cveId',
      header: 'CVE',
      cell: ({ row }) => (
        <span className="whitespace-nowrap font-mono text-sm font-semibold text-primary">
          {row.original.cveId}
        </span>
      ),
    },
    {
      id: 'epss',
      header: 'EPSS',
      cell: ({ row }) => {
        const { epssScore, epssPercentile } = row.original;
        if (epssScore == null) return DASH;
        return (
          <span className="flex items-baseline gap-1 whitespace-nowrap">
            <span className="text-sm font-semibold text-foreground">
              {formatPercent(epssScore, 0)}
            </span>
            <span className="text-xs text-muted-foreground">
              {formatPercentile(epssPercentile)}
            </span>
          </span>
        );
      },
    },
    {
      id: 'kev',
      header: 'KEV',
      cell: ({ row }) => {
        if (!row.original.kev) return DASH;
        const overdue = isKevOverdue(row.original.kevDueDate);
        return (
          <span
            className={cn(
              'inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold',
              overdue
                ? 'bg-destructive/10 text-destructive'
                : 'bg-severity-high/10 text-severity-high',
            )}
            title={
              row.original.kevDueDate ? `Remediation due ${row.original.kevDueDate}` : undefined
            }
          >
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
            {overdue ? 'Overdue' : 'KEV'}
          </span>
        );
      },
    },
    {
      id: 'exploit',
      header: 'Exploit',
      cell: ({ row }) =>
        row.original.exploitMaturity === 'NONE' ? (
          DASH
        ) : (
          <ExploitBadge maturity={row.original.exploitMaturity} />
        ),
    },
    {
      id: 'fix',
      header: 'Fix',
      cell: ({ row }) => (
        <FixBadge
          state={row.original.fixState}
          fixedVersions={row.original.fixedVersions}
          fixSource={row.original.fixSource}
        />
      ),
    },
    {
      id: 'match',
      header: 'Match',
      cell: ({ row }) =>
        row.original.matchConfidence ? (
          <MatchConfidenceBadge confidence={row.original.matchConfidence} />
        ) : (
          DASH
        ),
    },
    {
      id: 'affected',
      header: 'Affected',
      size: 240,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[240px]">
          <div className="truncate text-sm font-medium text-foreground">
            {row.original.productName ?? '—'}
          </div>
          <div
            className="truncate font-mono text-xs text-muted-foreground"
            title={row.original.componentPurl ?? undefined}
          >
            {componentLabel(row.original.componentName, row.original.componentVersion)}
          </div>
        </div>
      ),
    },
    {
      id: 'age',
      header: 'Age',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatRelativeDate(row.original.createdAt)}
        </span>
      ),
    },
  ];
}
