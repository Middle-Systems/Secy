import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

import { useIngestKev, useKevPage } from '@/api/queries';
import type { KEV } from '@/api/types';
import { DataTable } from '@/components/common/DataTable';
import { IngestButton } from '@/components/common/IngestButton';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { RecentIngestions } from '@/components/jobs/RecentIngestions';
import { Pagination } from '@/components/common/Pagination';
import { SearchInput } from '@/components/common/SearchInput';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import { KevRemediationModal } from './KevRemediationModal';
import { kevColumns } from './kev.columns';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

/**
 * KEV Database — the CISA Known Exploited Vulnerabilities catalog.
 *
 * Server-driven via `useKevPage`; search resets to page 0; manual refresh and
 * ingest both toast. Row action opens the {@link KevRemediationModal}.
 */
export function KevDatabaseView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<KEV | null>(null);

  const query = useKevPage({ page, size, search });
  const ingest = useIngestKev();

  useEffect(() => {
    if (query.isError) toast.error('Failed to sync with the local KEV database.');
  }, [query.isError]);

  const columns = useMemo(() => kevColumns(setSelected), []);

  const handleSearch = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Threat Intelligence table updated');
  };

  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="CISA Known Exploited Vulnerabilities"
        subtitle="Catalog of vulnerabilities with confirmed exploitation in the wild."
        actions={
          <>
            <SearchInput
              value={search}
              onDebouncedChange={handleSearch}
              placeholder="Search Vendor, Product, or CVE…"
              aria-label="Search the KEV catalog"
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
              label="Ingest Latest KEV"
              pendingLabel="Ingesting…"
              startMessage="Starting CISA KEV ingestion…"
              successMessage="Successfully synced with CISA"
              errorMessage="CISA API might be unreachable"
              onIngested={() => setPage(0)}
            />
          </>
        }
      />

      <RecentIngestions type="KEV" />

      {showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load the KEV catalog</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            The KEV service did not respond. Check that the backend is running, then retry.
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
            getRowId={(entry) => entry.cveId}
            emptyMessage="No entries found."
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

      <KevRemediationModal
        entry={selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      />
    </div>
  );
}
