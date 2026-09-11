import { useEffect, useMemo, useState } from 'react';
import { Loader2, Plus, RefreshCw, ServerOff, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { useAssets, useDeleteAsset } from '@/api/queries';
import type { AssetSummary, AssetType } from '@/api/types';
import { DataTable } from '@/components/common/DataTable';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { Pagination } from '@/components/common/Pagination';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
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

import { AssetDetailPanel } from './AssetDetailPanel';
import { assetTypeLabel } from './asset-type';
import { infrastructureColumns } from './infrastructure.columns';
import { ScanAssetModal } from './ScanAssetModal';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

const TYPE_OPTIONS: { value: AssetType | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Any type' },
  { value: 'CONTAINER_IMAGE', label: assetTypeLabel('CONTAINER_IMAGE') },
  { value: 'HOST', label: assetTypeLabel('HOST') },
  { value: 'SERVICE', label: assetTypeLabel('SERVICE') },
];

/**
 * Infrastructure — the asset inventory (Phase 4). Server-driven via
 * `useAssets`, ordered by name server-side. Follows the Actionable / KEV
 * views' shape: `DataTable` + `Pagination`, a row click opens
 * `AssetDetailPanel`, and a "Scan asset" action opens `ScanAssetModal`
 * (mirrors `UploadSbomModal`'s queue → poll → settle flow).
 */
export function InfrastructureView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [type, setType] = useState<AssetType | 'ALL'>('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AssetSummary | null>(null);

  const deleteAsset = useDeleteAsset();

  const query = useAssets({ page, size, type: type === 'ALL' ? undefined : type });

  useEffect(() => {
    if (query.isError) toast.error('Failed to load the asset inventory.');
  }, [query.isError]);

  const columns = useMemo(() => infrastructureColumns({ onDelete: setDeleteTarget }), []);
  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Infrastructure updated');
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      const summary = await deleteAsset.mutateAsync(deleteTarget.id);
      toast.success(
        `Deleted "${summary.name}" — ${formatInteger(summary.componentsRemoved)} component(s), ${formatInteger(summary.alertsRemoved)} alert(s) removed.`,
      );
      setDeleteTarget(null);
    } catch {
      toast.error(`Could not delete "${deleteTarget.name}".`);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="Infrastructure"
        subtitle="Hosts, container images and services scanned with Trivy or Grype, correlated against the funnel."
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
            <Button onClick={() => setScanOpen(true)}>
              <Plus className="h-4 w-4" />
              Scan asset
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card p-3">
        <Select
          value={type}
          onValueChange={(v) => {
            setType(v as AssetType | 'ALL');
            setPage(0);
          }}
        >
          <SelectTrigger className="h-9 w-[180px]" aria-label="Filter by asset type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TYPE_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <ServerOff className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load the asset inventory</p>
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
            emptyMessage="No assets yet — scan a container image, host or service to populate the inventory."
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

      <AssetDetailPanel
        id={selectedId}
        onOpenChange={(open) => {
          if (!open) setSelectedId(null);
        }}
      />

      <ScanAssetModal open={scanOpen} onOpenChange={setScanOpen} />

      <AlertDialog
        open={deleteTarget != null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{deleteTarget?.name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes the asset and every component and alert attached to it. This
              cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteAsset.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleDelete();
              }}
              disabled={deleteAsset.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteAsset.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              <Trash2 className="h-4 w-4" />
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
