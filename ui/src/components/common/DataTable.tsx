import { Fragment, useState, type ReactNode } from 'react';
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
} from '@tanstack/react-table';
import { ChevronDown, ChevronRight } from 'lucide-react';

import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';

export interface DataTableProps<TData> {
  /** TanStack column defs. Keep cells presentational — no data fetching. */
  columns: ColumnDef<TData, unknown>[];
  data: TData[];
  /** Show skeleton rows instead of data. */
  isLoading?: boolean;
  /** Skeleton row count while `isLoading`. Default 8. */
  skeletonRows?: number;
  /** Shown when `data` is empty and not loading. Default "No results." */
  emptyMessage?: ReactNode;
  /** Stable row id — needed for expansion state and good React keys. */
  getRowId?: (row: TData, index: number) => string;
  /** Row click handler. Adds a pointer cursor + hover affordance. */
  onRowClick?: (row: TData) => void;
  /**
   * Render an expandable detail panel under a row. When set, a chevron toggle
   * column is prepended automatically and rows become individually expandable
   * (click the chevron, or the row when `onRowClick` is not set).
   */
  renderSubRow?: (row: TData) => ReactNode;
  /** Extra classes on the scroll wrapper. */
  className?: string;
}

/**
 * Thin generic wrapper over `@tanstack/react-table` + the shadcn table
 * primitives. Server-paged by design — no built-in sorting or client paging
 * (pass a `Pagination` alongside).
 *
 * Header is styled like the Angular `thead.bg-light.text-muted.small.text-uppercase`.
 * The wrapper owns horizontal overflow; the shell owns page scroll.
 *
 * @example
 * const columns: ColumnDef<KEV, unknown>[] = [
 *   { accessorKey: 'cveId', header: 'CVE ID', cell: ({ row }) => <Mono>{row.original.cveId}</Mono> },
 * ];
 * <DataTable
 *   columns={columns}
 *   data={page.content}
 *   isLoading={isPending}
 *   getRowId={(k) => k.cveId}
 *   emptyMessage="No entries found."
 * />
 *
 * @example  // expandable rows (CVE view)
 * <DataTable columns={cols} data={rows} renderSubRow={(cve) => <CveDetail cve={cve} />} />
 */
export function DataTable<TData>({
  columns,
  data,
  isLoading = false,
  skeletonRows = 8,
  emptyMessage = 'No results.',
  getRowId,
  onRowClick,
  renderSubRow,
  className,
}: DataTableProps<TData>) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId,
  });

  const expandable = Boolean(renderSubRow);
  const leafCount = table.getAllLeafColumns().length;
  const totalCols = leafCount + (expandable ? 1 : 0);

  const toggle = (id: string) => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));

  const handleRowActivate = (row: Row<TData>) => {
    if (onRowClick) onRowClick(row.original);
    else if (expandable) toggle(row.id);
  };

  return (
    <div className={cn('w-full overflow-x-auto rounded-lg border border-border', className)}>
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50 hover:bg-muted/50">
            {expandable && <TableHead className="w-10" aria-label="Expand" />}
            {table.getFlatHeaders().map((header) => (
              <TableHead
                key={header.id}
                className="text-xs font-semibold uppercase tracking-wide text-muted-foreground"
                style={header.column.columnDef.size ? { width: header.column.columnDef.size } : undefined}
              >
                {header.isPlaceholder
                  ? null
                  : flexRender(header.column.columnDef.header, header.getContext())}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>

        <TableBody>
          {isLoading ? (
            Array.from({ length: skeletonRows }).map((_, r) => (
              <TableRow key={`s${r}`}>
                {Array.from({ length: totalCols }).map((__, c) => (
                  <TableCell key={c}>
                    <Skeleton className="h-4 w-full max-w-[160px]" />
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : table.getRowModel().rows.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell
                colSpan={totalCols}
                className="h-32 text-center text-sm text-muted-foreground"
              >
                {emptyMessage}
              </TableCell>
            </TableRow>
          ) : (
            table.getRowModel().rows.map((row) => {
              const isOpen = expanded[row.id] ?? false;
              const interactive = Boolean(onRowClick) || expandable;
              return (
                <Fragment key={row.id}>
                  <TableRow
                    data-state={isOpen ? 'selected' : undefined}
                    className={cn(interactive && 'cursor-pointer')}
                    onClick={interactive ? () => handleRowActivate(row) : undefined}
                  >
                    {expandable && (
                      <TableCell className="w-10">
                        <button
                          type="button"
                          aria-label={isOpen ? 'Collapse row' : 'Expand row'}
                          aria-expanded={isOpen}
                          className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggle(row.id);
                          }}
                        >
                          {isOpen ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </TableCell>
                    )}
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </TableCell>
                    ))}
                  </TableRow>

                  {expandable && isOpen && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell
                        colSpan={totalCols}
                        className="border-l-4 border-primary bg-muted/30 p-4"
                      >
                        {renderSubRow?.(row.original)}
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })
          )}
        </TableBody>
      </Table>
    </div>
  );
}
