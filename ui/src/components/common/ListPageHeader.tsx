import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

interface ListPageHeaderProps {
  /** Page title, e.g. "CISA Known Exploited Vulnerabilities". */
  title: string;
  /** One-line description under the title. */
  subtitle?: string;
  /**
   * Right-aligned action area — typically `<SearchInput />`, a refresh button
   * and an `<IngestButton />`. Wraps below the title on narrow screens.
   */
  actions?: ReactNode;
  className?: string;
}

/**
 * Shared header for the list / database views: title + subtitle on the left,
 * actions on the right. Start a view with this — no outer wrapper needed
 * (the shell already pads the page).
 *
 * @example
 * <ListPageHeader
 *   title="CISA Known Exploited Vulnerabilities"
 *   subtitle="Catalog of vulnerabilities with confirmed exploitation in the wild."
 *   actions={
 *     <>
 *       <SearchInput value={search} onDebouncedChange={onSearch} placeholder="Search…" />
 *       <Button variant="outline" size="icon" onClick={refetch}><RefreshCw /></Button>
 *       <IngestButton ingest={() => ingest.mutateAsync()} label="Ingest Latest KEV" />
 *     </>
 *   }
 * />
 */
export function ListPageHeader({ title, subtitle, actions, className }: ListPageHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">{title}</h1>
        {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {actions && (
        <div className="flex flex-wrap items-center gap-2 lg:flex-nowrap lg:justify-end">
          {actions}
        </div>
      )}
    </div>
  );
}
