import type { ColumnDef } from '@tanstack/react-table';
import { Biohazard } from 'lucide-react';

import type { KEV } from '@/api/types';
import { Button } from '@/components/ui/button';
import { formatDate } from '@/lib/format';
import { isKnownRansomware } from '@/components/dashboard/dashboard.helpers';

/** Column defs for the KEV table. `onViewSteps` opens the remediation modal. */
export function kevColumns(onViewSteps: (entry: KEV) => void): ColumnDef<KEV, unknown>[] {
  return [
    {
      accessorKey: 'cveId',
      header: 'CVE ID',
      cell: ({ row }) => (
        <span className="font-mono text-sm font-semibold text-primary">{row.original.cveId}</span>
      ),
    },
    {
      accessorKey: 'vendor',
      header: 'Vendor / Product',
      cell: ({ row }) => (
        <div className="min-w-0">
          <div className="truncate text-sm font-bold text-foreground">{row.original.vendor}</div>
          <div className="truncate text-xs text-muted-foreground">{row.original.product}</div>
        </div>
      ),
    },
    {
      accessorKey: 'name',
      header: 'Vulnerability Name',
      size: 320,
      cell: ({ row }) => (
        <span className="block max-w-[320px] truncate text-sm" title={row.original.name}>
          {row.original.name}
        </span>
      ),
    },
    {
      accessorKey: 'added',
      header: 'Date Added',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatDate(row.original.added)}
        </span>
      ),
    },
    {
      id: 'ransomware',
      header: 'Ransomware?',
      cell: ({ row }) =>
        isKnownRansomware(row.original) ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-destructive/10 px-2 py-0.5 text-xs font-semibold text-destructive">
            <Biohazard className="h-3.5 w-3.5" aria-hidden="true" />
            Confirmed
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">Unconfirmed</span>
        ),
    },
    {
      id: 'action',
      header: () => <span className="sr-only">Action</span>,
      cell: ({ row }) => (
        <div className="text-right">
          <Button
            variant="outline"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              onViewSteps(row.original);
            }}
          >
            View Steps
          </Button>
        </div>
      ),
    },
  ];
}
