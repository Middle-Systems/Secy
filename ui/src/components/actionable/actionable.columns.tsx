import type { ColumnDef } from '@tanstack/react-table';
import { ShieldAlert } from 'lucide-react';

import type { ActionableItem } from '@/api/types';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { formatPercent, formatPercentile, formatRelativeDate } from '@/lib/format';
import { cn } from '@/lib/utils';

import { COMPROMISE_TYPE_LABELS, componentLabel, isKevOverdue } from './actionable.helpers';
import { CompromiseConfidenceBadge } from './CompromiseConfidenceBadge';
import { ExploitBadge } from './ExploitBadge';
import { FixBadge } from './FixBadge';
import { MaliciousBadge } from './MaliciousBadge';
import { MatchConfidenceBadge } from './MatchConfidenceBadge';
import { TriageStateBadge } from './TriageStateBadge';

const DASH = <span className="text-xs text-muted-foreground">—</span>;

/** Tailwind classes for the "this row is different and urgent" treatment on a COMPROMISE row. */
export function actionableRowClassName(item: ActionableItem): string | undefined {
  return item.itemType === 'COMPROMISE'
    ? 'border-l-2 border-l-destructive bg-destructive/5 hover:bg-destructive/10'
    : undefined;
}

/**
 * Column defs for the Actionable Items table. Non-sortable by design — the sort
 * is fixed server-side (compromise tier first, then EPSS desc within the
 * vulnerability tier — see PHASE6-CONTRACT §4.6); row clicks open the detail
 * panel, wired in the view via `DataTable`'s `onRowClick`.
 *
 * Since Phase 6 a row may be either arm of the `/actionable` union
 * (`ActionableItem.itemType`). Every column that only makes sense for a CVE
 * (EPSS / KEV / Exploit / Fix / Match) renders a dash on a `COMPROMISE` row —
 * those fields arrive `null`, never a misleading zero — and the identity
 * column swaps the CVE id for the finding's IOC id + type, badged distinctly.
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
      id: 'identity',
      header: 'CVE',
      cell: ({ row }) => {
        const item = row.original;
        if (item.itemType === 'COMPROMISE') {
          return (
            <div className="flex flex-col gap-1">
              <MaliciousBadge />
              <span
                className="whitespace-nowrap font-mono text-xs text-muted-foreground"
                title={item.matchedOn ?? undefined}
              >
                {(item.compromiseType && COMPROMISE_TYPE_LABELS[item.compromiseType]) ||
                  item.compromiseType}
                {item.iocId ? ` · ${item.iocId}` : ''}
              </span>
            </div>
          );
        }
        return (
          <span className="whitespace-nowrap font-mono text-sm font-semibold text-primary">
            {item.cveId}
          </span>
        );
      },
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
      cell: ({ row }) => {
        const { exploitMaturity } = row.original;
        return !exploitMaturity || exploitMaturity === 'NONE' ? (
          DASH
        ) : (
          <ExploitBadge maturity={exploitMaturity} />
        );
      },
    },
    {
      id: 'fix',
      header: 'Fix',
      cell: ({ row }) => {
        const { fixState, fixedVersions, fixSource } = row.original;
        if (!fixState) return DASH;
        return <FixBadge state={fixState} fixedVersions={fixedVersions} fixSource={fixSource} />;
      },
    },
    {
      id: 'match',
      header: 'Match',
      cell: ({ row }) => {
        const { matchConfidence, compromiseConfidence } = row.original;
        if (matchConfidence) return <MatchConfidenceBadge confidence={matchConfidence} />;
        if (compromiseConfidence) return <CompromiseConfidenceBadge confidence={compromiseConfidence} />;
        return DASH;
      },
    },
    {
      id: 'affected',
      header: 'Affected',
      size: 240,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[240px]">
          <div className="truncate text-sm font-medium text-foreground">
            {row.original.assetName ?? row.original.productName ?? '—'}
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
    {
      id: 'triage',
      header: 'Triage',
      cell: ({ row }) => {
        const { triageState, assigneeName } = row.original;
        return (
          <div className="flex flex-col items-start gap-1">
            <TriageStateBadge state={triageState} />
            {assigneeName && (
              <span className="truncate text-xs text-muted-foreground" title={assigneeName}>
                {assigneeName}
              </span>
            )}
          </div>
        );
      },
    },
  ];
}
