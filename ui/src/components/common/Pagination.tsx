import { ChevronLeft, ChevronRight } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatInteger } from '@/lib/format';
import { cn } from '@/lib/utils';

import { ELLIPSIS, getVisiblePages, pageRange } from './pagination.helpers';

export interface PaginationProps {
  /** Current page, 0-indexed (Spring `Page.number`). */
  page: number;
  /** Page size (Spring `Page.size`). */
  size: number;
  /** Total row count across all pages (`Page.totalElements`). */
  totalElements: number;
  /** Total page count (`Page.totalPages`). */
  totalPages: number;
  /** Called with the next 0-indexed page. Bounds are enforced here. */
  onPageChange: (page: number) => void;
  /** Called with the next size. Omit to hide the page-size selector. */
  onSizeChange?: (size: number) => void;
  /** Options for the size selector. Default `[15, 25, 50]`. */
  pageSizeOptions?: number[];
  className?: string;
}

/**
 * Server-pagination controls for a Spring `Page`: a "Showing X–Y of Z" summary,
 * prev/next buttons, a windowed page-number list with ellipses
 * ({@link getVisiblePages}), and an optional page-size selector.
 *
 * Renders nothing when there is only one page and no size selector.
 *
 * @example
 * <Pagination
 *   page={data.number}
 *   size={data.size}
 *   totalElements={data.totalElements}
 *   totalPages={data.totalPages}
 *   onPageChange={setPage}
 *   onSizeChange={(s) => { setSize(s); setPage(0); }}
 * />
 */
export function Pagination({
  page,
  size,
  totalElements,
  totalPages,
  onPageChange,
  onSizeChange,
  pageSizeOptions = [15, 25, 50],
  className,
}: PaginationProps) {
  const { from, to } = pageRange(page, size, totalElements);
  const pages = getVisiblePages(totalPages, page);

  const go = (next: number) => {
    const clamped = Math.min(Math.max(next, 0), Math.max(totalPages - 1, 0));
    if (clamped !== page) onPageChange(clamped);
  };

  if (totalPages <= 1 && !onSizeChange) return null;

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-between gap-4 sm:flex-row',
        className,
      )}
    >
      <p className="text-sm text-muted-foreground">
        Showing <span className="font-medium text-foreground">{formatInteger(from)}</span>–
        <span className="font-medium text-foreground">{formatInteger(to)}</span> of{' '}
        <span className="font-medium text-foreground">{formatInteger(totalElements)}</span>
      </p>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => go(page - 1)}
          disabled={page <= 0}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
          <span className="hidden sm:inline">Previous</span>
        </Button>

        <ul className="flex items-center gap-1">
          {pages.map((token, i) =>
            token === ELLIPSIS ? (
              <li
                key={`e${i}`}
                className="px-2 text-sm text-muted-foreground"
                aria-hidden="true"
              >
                …
              </li>
            ) : (
              <li key={token}>
                <Button
                  variant={token === page ? 'default' : 'ghost'}
                  size="icon"
                  className="h-9 w-9"
                  aria-label={`Page ${token + 1}`}
                  aria-current={token === page ? 'page' : undefined}
                  onClick={() => go(token)}
                >
                  {token + 1}
                </Button>
              </li>
            ),
          )}
        </ul>

        <Button
          variant="outline"
          size="sm"
          onClick={() => go(page + 1)}
          disabled={page >= totalPages - 1}
          aria-label="Next page"
        >
          <span className="hidden sm:inline">Next</span>
          <ChevronRight className="h-4 w-4" />
        </Button>

        {onSizeChange && (
          <Select
            value={String(size)}
            onValueChange={(v) => onSizeChange(Number(v))}
          >
            <SelectTrigger className="h-9 w-[130px]" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {pageSizeOptions.map((opt) => (
                <SelectItem key={opt} value={String(opt)}>
                  {opt} / page
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>
    </div>
  );
}
