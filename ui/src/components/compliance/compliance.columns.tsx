import type { ColumnDef } from '@tanstack/react-table';
import { Loader2, RefreshCw } from 'lucide-react';

import type { ComplianceReportSummary } from '@/api/types';
import { Button } from '@/components/ui/button';
import { formatInteger, formatRelativeDate } from '@/lib/format';
import { cn } from '@/lib/utils';

import { ComplianceReportStatusBadge, ControlBreakdownBar } from './compliance.helpers';

const DASH = <span className="text-xs text-muted-foreground">—</span>;

interface ComplianceColumnsOptions {
  /** Row-scoped re-scan action. */
  onRescan: (report: ComplianceReportSummary) => void;
  /** Ids of reports whose re-scan is in flight, to disable + spin their button. */
  rescanningIds: Set<string>;
  /** Opens the asset's own detail panel without also opening the report row. */
  onOpenAsset: (assetId: string) => void;
}

/**
 * Column defs for the Compliance report table. Row click opens the report
 * detail panel (wired via `DataTable`'s `onRowClick` in `ComplianceView`);
 * the asset link and the re-scan button both stop that click from bubbling.
 */
export function complianceColumns({
  onRescan,
  rescanningIds,
  onOpenAsset,
}: ComplianceColumnsOptions): ColumnDef<ComplianceReportSummary, unknown>[] {
  return [
    {
      id: 'title',
      header: 'Report',
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[280px]">
          <div className="truncate text-sm font-semibold text-foreground">
            {row.original.title ?? row.original.benchmarkId ?? 'Untitled report'}
          </div>
          {row.original.benchmarkId && (
            <div className="truncate font-mono text-xs text-muted-foreground">
              {row.original.benchmarkId}
              {row.original.version ? ` · ${row.original.version}` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      id: 'asset',
      header: 'Asset',
      cell: ({ row }) =>
        row.original.assetId && row.original.assetName ? (
          <button
            type="button"
            className="whitespace-nowrap font-mono text-sm text-primary hover:underline"
            onClick={(event) => {
              event.stopPropagation();
              onOpenAsset(row.original.assetId!);
            }}
          >
            {row.original.assetName}
          </button>
        ) : (
          DASH
        ),
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) => <ComplianceReportStatusBadge status={row.original.status} />,
    },
    {
      id: 'controls',
      header: 'Controls',
      size: 160,
      cell: ({ row }) => (
        <div className="flex flex-col gap-1">
          <ControlBreakdownBar {...row.original} />
          <span className="text-xs text-muted-foreground">
            {formatInteger(row.original.passedControls)} pass ·{' '}
            {formatInteger(row.original.failedControls)} fail ·{' '}
            {formatInteger(row.original.skippedControls)} skip
          </span>
        </div>
      ),
    },
    {
      id: 'actionable',
      header: 'Actionable',
      cell: ({ row }) => (
        <span
          className={cn(
            'inline-flex items-center rounded-full px-2 py-0.5 text-sm font-bold',
            row.original.actionableItems > 0
              ? 'bg-destructive/10 text-destructive'
              : 'bg-muted text-muted-foreground',
          )}
        >
          {formatInteger(row.original.actionableItems)}
        </span>
      ),
    },
    {
      id: 'scannedAt',
      header: 'Scanned',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatRelativeDate(row.original.scannedAt ?? row.original.createdAt)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => {
        const rescanning = rescanningIds.has(row.original.id);
        return (
          <Button
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-primary"
            aria-label={`Re-scan ${row.original.title ?? row.original.benchmarkId ?? 'report'}`}
            title="Re-scan report"
            disabled={rescanning}
            onClick={(event) => {
              event.stopPropagation();
              onRescan(row.original);
            }}
          >
            {rescanning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
          </Button>
        );
      },
    },
  ];
}
