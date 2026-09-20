import type { ColumnDef } from '@tanstack/react-table';
import { Trash2 } from 'lucide-react';

import type { SourceConnector } from '@/api/types';
import { Button } from '@/components/ui/button';
import { formatInteger, formatRelativeDate } from '@/lib/format';

import { ConnectorSyncCell, ConnectorTypeIcon } from './connectors.helpers';

interface ConnectorsColumnsOptions {
  /** Row-scoped delete action — opens the confirmation, doesn't delete directly. */
  onDelete: (connector: SourceConnector) => void;
}

/** Column defs for the Connectors table. */
export function connectorsColumns({
  onDelete,
}: ConnectorsColumnsOptions): ColumnDef<SourceConnector, unknown>[] {
  return [
    {
      id: 'type',
      header: 'Type',
      cell: ({ row }) => (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-muted-foreground">
          <ConnectorTypeIcon type={row.original.type} />
          GitHub
        </span>
      ),
    },
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm font-semibold text-foreground">
          {row.original.name}
        </span>
      ),
    },
    {
      accessorKey: 'scope',
      header: 'Scope',
      cell: ({ row }) => (
        <span className="font-mono text-sm text-foreground">{row.original.scope}</span>
      ),
    },
    {
      id: 'repos',
      header: 'Repos',
      cell: ({ row }) => {
        const count = row.original.repoAllowlist.length;
        return (
          <span className="text-sm text-muted-foreground">
            {count === 0 ? 'All repos' : `${formatInteger(count)} repo${count === 1 ? '' : 's'}`}
          </span>
        );
      },
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) => <ConnectorSyncCell connector={row.original} />,
    },
    {
      id: 'lastSynced',
      header: 'Last Synced',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatRelativeDate(row.original.lastSyncedAt)}
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
          title="Delete connector"
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
