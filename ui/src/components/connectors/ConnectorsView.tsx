import { useEffect, useMemo, useState } from 'react';
import { Loader2, Plug, Plus, RefreshCw, ServerOff, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { useConnectors, useDeleteConnector } from '@/api/queries';
import type { SourceConnector } from '@/api/types';
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
import { cn } from '@/lib/utils';

import { AddConnectorModal } from './AddConnectorModal';
import { connectorsColumns } from './connectors.columns';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

/**
 * Connectors — agentless source/cloud connectors (Phase 6b). A GitHub
 * connector enumerates repos under a GitHub org/user and pulls their
 * dependency-graph SBOMs through the exact ingest path a manual SPDX upload
 * takes (one repo -> one `Product`); an AWS connector enumerates EC2/ECR/
 * Lambda in a region via Inspector2; an Azure connector enumerates VMs/ACR
 * registries in a subscription via Defender for Cloud — all three funnel
 * through the same `Asset`/scan pipeline Trivy/Grype use. Follows the
 * Infrastructure/Compliance views' shape: `DataTable` + `Pagination`, an "Add
 * connector" action opens `AddConnectorModal`, and "Sync now" (per row, in
 * `connectorsColumns`) drives the same queue -> poll -> settle flow as
 * `ScanAssetModal` — inline on the row rather than behind a modal, since
 * there's no file to pick for this action, just a button press.
 *
 * No detail panel: a connector carries only the fields already visible in
 * the row (type/name/scope/allowlist/status/last synced) — a drill-down
 * would just repeat the row, so it's deferred until there's real detail to
 * show (e.g. per-repo sync results).
 */
export function ConnectorsView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [addOpen, setAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SourceConnector | null>(null);

  const deleteConnector = useDeleteConnector();
  const query = useConnectors({ page, size });

  useEffect(() => {
    if (query.isError) toast.error('Failed to load connectors.');
  }, [query.isError]);

  const columns = useMemo(() => connectorsColumns({ onDelete: setDeleteTarget }), []);
  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Connectors updated');
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteConnector.mutateAsync(deleteTarget.id);
      toast.success(`Deleted "${deleteTarget.name}". Products and SBOMs it created are untouched.`);
      setDeleteTarget(null);
    } catch {
      toast.error(`Could not delete "${deleteTarget.name}".`);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="Connectors"
        subtitle="Source & cloud connectors that sync their own inventory — GitHub, AWS and Azure, agentless."
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
            <Button onClick={() => setAddOpen(true)}>
              <Plus className="h-4 w-4" />
              Add connector
            </Button>
          </>
        }
      />

      {showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <ServerOff className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load connectors</p>
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
            emptyMessage={
              <span className="inline-flex items-center gap-2">
                <Plug className="h-4 w-4" aria-hidden="true" />
                No connectors yet — add one to pull inventory from GitHub, AWS or Azure automatically.
              </span>
            }
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

      <AddConnectorModal open={addOpen} onOpenChange={setAddOpen} />

      <AlertDialog
        open={deleteTarget != null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{deleteTarget?.name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This only stops future syncs for this connector. It does NOT remove the products,
              SBOMs or alerts it already created — those are real inventory now, independent of the
              connector that introduced them, exactly like a manually-uploaded SBOM outlives the
              upload that created it. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteConnector.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleDelete();
              }}
              disabled={deleteConnector.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteConnector.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              <Trash2 className="h-4 w-4" />
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
