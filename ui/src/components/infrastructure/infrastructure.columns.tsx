import type { ColumnDef } from '@tanstack/react-table';
import { Trash2 } from 'lucide-react';

import type { AssetSummary } from '@/api/types';
import { Button } from '@/components/ui/button';
import { formatInteger, formatRelativeDate } from '@/lib/format';
import { cn } from '@/lib/utils';

import { assetTypeLabel } from './asset-type';
import { AssetScannerBadge, AssetStatusBadge, AssetTypeIcon } from './infrastructure.helpers';

const DASH = <span className="text-xs text-muted-foreground">—</span>;

interface InfrastructureColumnsOptions {
  /** Row-scoped delete action — opens the confirmation, doesn't delete directly. */
  onDelete: (asset: AssetSummary) => void;
}

/**
 * Column defs for the Infrastructure asset table. Row click opens the detail
 * panel (wired via `DataTable`'s `onRowClick` in `InfrastructureView`); the
 * delete button stops that click from bubbling so it doesn't also open the
 * panel.
 */
export function infrastructureColumns({
  onDelete,
}: InfrastructureColumnsOptions): ColumnDef<AssetSummary, unknown>[] {
  return [
    {
      id: 'type',
      header: 'Type',
      cell: ({ row }) => (
        <span
          className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-muted-foreground"
          title={assetTypeLabel(row.original.type)}
        >
          <AssetTypeIcon type={row.original.type} />
          {assetTypeLabel(row.original.type)}
        </span>
      ),
    },
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <span className="whitespace-nowrap font-mono text-sm font-semibold text-foreground">
          {row.original.name}
        </span>
      ),
    },
    {
      id: 'product',
      header: 'Product',
      cell: ({ row }) =>
        row.original.productName ? (
          <span className="truncate text-sm text-foreground">{row.original.productName}</span>
        ) : (
          DASH
        ),
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) => <AssetStatusBadge status={row.original.status} />,
    },
    {
      id: 'scanner',
      header: 'Scanner',
      cell: ({ row }) => <AssetScannerBadge scanner={row.original.scanner} />,
    },
    {
      id: 'components',
      header: 'Components',
      cell: ({ row }) => (
        <span className="text-sm text-foreground">
          {formatInteger(row.original.componentCount)}
        </span>
      ),
    },
    {
      id: 'actionable',
      header: 'Actionable',
      cell: ({ row }) => (
        <span
          className={cn(
            'inline-flex items-center rounded-full px-2 py-0.5 text-sm font-bold',
            row.original.actionableCount > 0
              ? 'bg-destructive/10 text-destructive'
              : 'bg-muted text-muted-foreground',
          )}
        >
          {formatInteger(row.original.actionableCount)}
        </span>
      ),
    },
    {
      id: 'lastScanned',
      header: 'Last Scanned',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatRelativeDate(row.original.lastScannedAt)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="icon"
          className="text-muted-foreground hover:text-destructive"
          aria-label={`Delete ${row.original.name}`}
          title="Delete asset"
          onClick={(event) => {
            event.stopPropagation();
            onDelete(row.original);
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
    },
  ];
}
