import { useState, type ReactNode } from 'react';
import { Loader2, ShieldAlert, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { useAssetDetail, useDeleteAsset } from '@/api/queries';
import type { ActionableItemType, AssetDetail, TriageSnapshot } from '@/api/types';
import { actionableColumns, actionableRowClassName } from '@/components/actionable/actionable.columns';
import { triageSnapshotOf } from '@/components/actionable/actionable.helpers';
import { ActionableDetailPanel } from '@/components/actionable/ActionableDetailPanel';
import { DataTable } from '@/components/common/DataTable';
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
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { EM_DASH, formatDateTime, formatInteger, formatRelativeDate } from '@/lib/format';

import { assetTypeLabel } from './asset-type';
import { AssetScannerBadge, AssetStatusBadge, AssetTypeIcon } from './infrastructure.helpers';

interface AssetDetailPanelProps {
  /** Asset id to load, or `null` when the panel is closed. */
  id: string | null;
  onOpenChange: (open: boolean) => void;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <h3 className="mb-2 border-b border-border pb-1 text-xs font-bold uppercase tracking-wide text-primary">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-0.5 text-sm">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className="min-w-0 text-right font-medium text-foreground">{value}</span>
    </div>
  );
}

function Body({ detail, onDeleted }: { detail: AssetDetail; onDeleted: () => void }) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [selectedActionableId, setSelectedActionableId] = useState<string | null>(null);
  const [selectedActionableType, setSelectedActionableType] =
    useState<ActionableItemType | null>(null);
  const [selectedActionableTriage, setSelectedActionableTriage] =
    useState<TriageSnapshot | null>(null);
  const deleteAsset = useDeleteAsset();
  const actionColumns = actionableColumns();
  const items = detail.actionableItems.content;

  const handleDelete = async () => {
    try {
      const summary = await deleteAsset.mutateAsync(detail.id);
      toast.success(
        `Deleted "${summary.name}" — ${formatInteger(summary.componentsRemoved)} component(s), ${formatInteger(summary.alertsRemoved)} alert(s) removed.`,
      );
      setConfirmOpen(false);
      onDeleted();
    } catch {
      toast.error(`Could not delete "${detail.name}".`);
    }
  };

  return (
    <div className="mt-4 flex flex-col gap-6 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2 py-0.5 text-xs font-semibold text-muted-foreground">
          <AssetTypeIcon type={detail.type} />
          {assetTypeLabel(detail.type)}
        </span>
        <AssetStatusBadge status={detail.status} />
        <AssetScannerBadge scanner={detail.scanner} />
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto text-muted-foreground hover:text-destructive"
          onClick={() => setConfirmOpen(true)}
        >
          <Trash2 className="h-4 w-4" />
          Delete asset
        </Button>
      </div>

      <Section title="Asset">
        <Row label="Name" value={<span className="font-mono">{detail.name}</span>} />
        <Row label="Linked product" value={detail.productName ?? EM_DASH} />
        <Row label="Components" value={formatInteger(detail.componentCount)} />
        <Row label="Actionable findings" value={formatInteger(detail.actionableCount)} />
        <Row label="Last scanned" value={formatRelativeDate(detail.lastScannedAt)} />
        <Row label="Created" value={formatDateTime(detail.createdAt)} />
      </Section>

      {detail.declaredCpes.length > 0 && (
        <Section title={`Declared CPEs (${detail.declaredCpes.length})`}>
          <ul className="flex flex-col gap-1">
            {detail.declaredCpes.map((cpe) => (
              <li key={cpe} className="break-all font-mono text-xs text-muted-foreground">
                {cpe}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title={`Actionable items (${detail.actionableItems.totalElements})`}>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Nothing actionable on this asset right now.
          </p>
        ) : (
          <DataTable
            columns={actionColumns}
            data={items}
            getRowId={(entry) => entry.id}
            onRowClick={(entry) => {
              setSelectedActionableId(entry.id);
              setSelectedActionableType(entry.itemType);
              setSelectedActionableTriage(triageSnapshotOf(entry));
            }}
            rowClassName={actionableRowClassName}
            emptyMessage="Nothing actionable on this asset right now."
          />
        )}
      </Section>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{detail.name}”?</AlertDialogTitle>
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
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <ActionableDetailPanel
        id={selectedActionableId}
        itemType={selectedActionableType}
        initialTriage={selectedActionableTriage}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedActionableId(null);
            setSelectedActionableType(null);
            setSelectedActionableTriage(null);
          }
        }}
      />
    </div>
  );
}

/**
 * Right-hand detail sheet for one asset, driven by {@link useAssetDetail}.
 * Mirrors `ActionableDetailPanel`'s mechanics. Its actionable items reuse
 * `actionableColumns()` and, on click, `ActionableDetailPanel` itself —
 * these are the exact same `ActionableItem` shape, so there is nothing
 * asset-specific to render differently.
 */
export function AssetDetailPanel({ id, onOpenChange }: AssetDetailPanelProps) {
  const query = useAssetDetail(id ?? undefined);

  return (
    <Sheet open={id != null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="font-mono">{query.data?.name ?? 'Asset'}</SheetTitle>
          <SheetDescription>
            Asset metadata and the findings correlated against it.
          </SheetDescription>
        </SheetHeader>

        {query.isPending ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">Loading asset…</p>
          </div>
        ) : query.isError || !query.data ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">Could not load this asset.</p>
          </div>
        ) : (
          <Body detail={query.data} onDeleted={() => onOpenChange(false)} />
        )}
      </SheetContent>
    </Sheet>
  );
}
