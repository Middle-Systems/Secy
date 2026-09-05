import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, TrendingUp } from 'lucide-react';
import { toast } from 'sonner';

import { useEpssPage, useIngestEpss } from '@/api/queries';
import { DataTable } from '@/components/common/DataTable';
import { IngestButton } from '@/components/common/IngestButton';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { Pagination } from '@/components/common/Pagination';
import { SearchInput } from '@/components/common/SearchInput';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import { epssColumns } from './epss.columns';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

/**
 * EPSS Database — the FIRST Exploit Prediction Scoring System feed.
 *
 * Server-driven via `useEpssPage`; search and ingest both reset to page 0.
 * Manual refresh and errors toast locally (the mutation hook stays quiet).
 */
export function EpssDatabaseView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [search, setSearch] = useState('');

  const query = useEpssPage({ page, size, search });
  const ingest = useIngestEpss();

  useEffect(() => {
    if (query.isError) toast.error('Failed to sync with the local EPSS database.');
  }, [query.isError]);

  const columns = useMemo(() => epssColumns(), []);

  const handleSearch = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Exploit Prediction Scoring table updated');
  };

  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="Exploit Prediction Scoring System"
        subtitle="Data-driven probability that a vulnerability will be exploited in the wild."
        actions={
          <>
            <SearchInput
              value={search}
              onDebouncedChange={handleSearch}
              placeholder="Search by CVE…"
              aria-label="Search EPSS by CVE"
              className="w-full sm:w-[340px]"
            />
            <Button
              variant="outline"
              size="icon"
              onClick={handleRefresh}
              disabled={query.isFetching}
              title="Reload table data"
              aria-label="Reload table data"
            >
              <RefreshCw className={cn('h-4 w-4', query.isFetching && 'animate-spin')} />
            </Button>
            <IngestButton
              ingest={() => ingest.mutateAsync()}
              label="Ingest Latest EPSS"
              pendingLabel="Ingesting…"
              startMessage="Starting EPSS ingestion…"
              successMessage="Successfully synced"
              errorMessage="EPSS API might be unreachable"
              onIngested={() => setPage(0)}
            />
          </>
        }
      />

      {showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <TrendingUp className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load EPSS scores</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            The EPSS service did not respond. Check that the backend is running, then retry.
          </p>
          <Button variant="outline" size="sm" className="mt-2" onClick={handleRefresh}>
            Retry
          </Button>
        </div>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={rows}
            isLoading={query.isPending}
            skeletonRows={size > 15 ? 15 : size}
            getRowId={(entry) => entry.cve}
            emptyMessage="No EPSS records found."
          />

          {query.data && (
            <Pagination
              page={query.data.number}
              size={query.data.size}
              totalElements={query.data.totalElements}
              totalPages={query.data.totalPages}
              onPageChange={setPage}
              onSizeChange={(next) => {
                setSize(next);
                setPage(0);
              }}
              pageSizeOptions={PAGE_SIZE_OPTIONS}
            />
          )}
        </>
      )}
    </div>
  );
}
