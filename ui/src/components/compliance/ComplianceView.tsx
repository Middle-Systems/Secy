import { useEffect, useMemo, useState } from 'react';
import { Plus, RefreshCw, ServerOff } from 'lucide-react';
import { toast } from 'sonner';

import { useComplianceReports, useRescanComplianceReport } from '@/api/queries';
import type { ComplianceReportSummary } from '@/api/types';
import { DataTable } from '@/components/common/DataTable';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { Pagination } from '@/components/common/Pagination';
import { AssetDetailPanel } from '@/components/infrastructure/AssetDetailPanel';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import { complianceColumns } from './compliance.columns';
import { ComplianceReportDetailPanel } from './ComplianceReportDetailPanel';
import { UploadComplianceReportModal } from './UploadComplianceReportModal';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

/**
 * Compliance — CIS/Docker benchmark audits (Phase 5). Server-driven via
 * `useComplianceReports`, newest first. Follows the Infrastructure view's
 * shape: `DataTable` + `Pagination`, a row click opens
 * `ComplianceReportDetailPanel`, and an "Upload report" action opens
 * `UploadComplianceReportModal` (mirrors `ScanAssetModal`'s queue → poll →
 * settle flow). The audited asset's name cross-links to `AssetDetailPanel`,
 * the same way `ActionableView` links to it from a row's "Affected" cell.
 */
export function ComplianceView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [rescanningIds, setRescanningIds] = useState<Set<string>>(new Set());

  const rescan = useRescanComplianceReport();
  const query = useComplianceReports({ page, size });

  useEffect(() => {
    if (query.isError) toast.error('Failed to load compliance reports.');
  }, [query.isError]);

  const handleRescan = async (report: ComplianceReportSummary) => {
    setRescanningIds((prev) => new Set(prev).add(report.id));
    try {
      await rescan.mutateAsync(report.id);
      toast.success(
        `Re-scan queued for "${report.title ?? report.benchmarkId ?? report.id}" — open the report to track progress.`,
      );
    } catch {
      toast.error(
        `Could not queue a re-scan for "${report.title ?? report.benchmarkId ?? report.id}".`,
      );
    } finally {
      setRescanningIds((prev) => {
        const next = new Set(prev);
        next.delete(report.id);
        return next;
      });
    }
  };

  const columns = useMemo(
    () =>
      complianceColumns({
        onRescan: (report) => void handleRescan(report),
        rescanningIds,
        onOpenAsset: setSelectedAssetId,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rescanningIds],
  );

  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Compliance reports updated');
  };

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="Compliance"
        subtitle="CIS/Docker benchmark audits: control pass/fail coverage, misconfigurations with remediation, and the vulnerability alerts they raise."
        actions={
          <>
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
            <Button onClick={() => setUploadOpen(true)}>
              <Plus className="h-4 w-4" />
              Upload report
            </Button>
          </>
        }
      />

      {showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <ServerOff className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load compliance reports</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            The service did not respond. Check that the backend is running, then retry.
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
            getRowId={(entry) => entry.id}
            onRowClick={(entry) => setSelectedId(entry.id)}
            emptyMessage="No compliance reports yet — upload a `trivy --compliance` JSON report to audit an asset."
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

      <ComplianceReportDetailPanel
        id={selectedId}
        onOpenChange={(open) => {
          if (!open) setSelectedId(null);
        }}
        onOpenAsset={(assetId) => setSelectedAssetId(assetId)}
      />

      <AssetDetailPanel
        id={selectedAssetId}
        onOpenChange={(open) => {
          if (!open) setSelectedAssetId(null);
        }}
      />

      <UploadComplianceReportModal open={uploadOpen} onOpenChange={setUploadOpen} />
    </div>
  );
}
