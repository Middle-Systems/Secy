import { useEffect, useMemo, useState } from 'react';
import type { RowSelectionState } from '@tanstack/react-table';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

import { useActionablePage, useAssets, useBulkTriagePatch, useUsers } from '@/api/queries';
import type {
  ActionableFilters,
  ActionableItemType,
  ActionableReason,
  BulkTriagePatchPayload,
  CompromiseConfidence,
  MatchConfidence,
  TriageSnapshot,
  TriageState,
} from '@/api/types';
import { DataTable } from '@/components/common/DataTable';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { Pagination } from '@/components/common/Pagination';
import { AssetDetailPanel } from '@/components/infrastructure/AssetDetailPanel';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { TooltipProvider } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

import { actionableColumns, actionableRowClassName } from './actionable.columns';
import {
  readTogglePrefs,
  TRIAGE_STATE_LABELS,
  TRIAGE_STATES,
  triageSnapshotOf,
  userLabel,
  writeTogglePrefs,
  type ActionableTogglePrefs,
} from './actionable.helpers';
import { ActionableDetailPanel } from './ActionableDetailPanel';

const PAGE_SIZE_OPTIONS = [15, 25, 50];

const REASON_OPTIONS: { value: ActionableReason | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Any reason' },
  { value: 'KEV', label: 'KEV only' },
  { value: 'EPSS_HIGH', label: 'High EPSS only' },
  { value: 'KEV_AND_EPSS_HIGH', label: 'KEV + high EPSS' },
];

const MIN_CVSS_OPTIONS: { value: string; label: string }[] = [
  { value: 'ALL', label: 'Any CVSS' },
  { value: '4', label: 'CVSS ≥ 4 (Medium+)' },
  { value: '7', label: 'CVSS ≥ 7 (High+)' },
  { value: '9', label: 'CVSS ≥ 9 (Critical)' },
];

const MATCH_CONFIDENCE_OPTIONS: { value: MatchConfidence | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Any match confidence' },
  { value: 'EXACT', label: 'Exact match only' },
  { value: 'RANGE', label: 'Range match only' },
  { value: 'HEURISTIC', label: 'Heuristic match only' },
];

const ITEM_TYPE_OPTIONS: { value: ActionableItemType | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Vulnerabilities + compromise' },
  { value: 'VULNERABILITY', label: 'Vulnerabilities only' },
  { value: 'COMPROMISE', label: 'Compromise findings only' },
];

const CONFIDENCE_OPTIONS: { value: CompromiseConfidence | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Any confidence' },
  { value: 'CONFIRMED', label: 'Confirmed only' },
  { value: 'LIKELY', label: 'Likely only' },
  { value: 'INVESTIGATE', label: 'Investigate only' },
];

/** `ALL` maps to omitting `state` entirely — the backend's own "default view" (Phase 7). */
const TRIAGE_FILTER_OPTIONS: { value: TriageState | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Default view' },
  ...TRIAGE_STATES.map((s) => ({ value: s, label: TRIAGE_STATE_LABELS[s] })),
];

/** Sentinel for "leave this field alone" in the bulk-action bar's selects. */
const NO_CHANGE = 'NO_CHANGE';

/**
 * Actionable Items — the funnel output (KEV-listed OR EPSS > threshold), the
 * home screen. Server-driven via `useActionablePage`; sort is fixed server-side
 * (EPSS desc). The two opt-in toggles are remembered per-user in localStorage.
 */
export function ActionableView() {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(15);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedItemType, setSelectedItemType] = useState<ActionableItemType | null>(null);
  const [selectedTriage, setSelectedTriage] = useState<TriageSnapshot | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const [prefs, setPrefs] = useState<ActionableTogglePrefs>(() => readTogglePrefs());
  const [reason, setReason] = useState<ActionableReason | 'ALL'>('ALL');
  const [minCvss, setMinCvss] = useState<string>('ALL');
  const [matchConfidence, setMatchConfidence] = useState<MatchConfidence | 'ALL'>('ALL');
  const [assetId, setAssetId] = useState<string>('ALL');
  const [itemType, setItemType] = useState<ActionableItemType | 'ALL'>('ALL');
  const [confidence, setConfidence] = useState<CompromiseConfidence | 'ALL'>('ALL');
  const [triageStateFilter, setTriageStateFilter] = useState<TriageState | 'ALL'>('ALL');

  // Row selection for the bulk-action bar (Phase 7) — keyed by `ActionableItem.id`,
  // same convention `getRowId` already uses below.
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [bulkState, setBulkState] = useState<TriageState | typeof NO_CHANGE>(NO_CHANGE);
  const [bulkAssigneeId, setBulkAssigneeId] = useState<string>(NO_CHANGE);

  useEffect(() => {
    writeTogglePrefs(prefs);
  }, [prefs]);

  // Populates the asset filter select. A flat list is enough at MVP scale — this
  // mirrors the other filter selects' static option lists, just sourced from the API.
  const assetsQuery = useAssets({ size: 100 });
  const assetOptions = assetsQuery.data?.content ?? [];

  // Populates the bulk-action bar's assignee select.
  const usersQuery = useUsers();
  const users = usersQuery.data ?? [];

  const filters: ActionableFilters = useMemo(
    () => ({
      fixState: prefs.onlyWithFix ? 'FIXED' : undefined,
      minExploitMaturity: prefs.onlyWithExploit ? 'POC' : undefined,
      reason: reason === 'ALL' ? undefined : reason,
      minCvss: minCvss === 'ALL' ? undefined : Number(minCvss),
      matchConfidence: matchConfidence === 'ALL' ? undefined : matchConfidence,
      assetId: assetId === 'ALL' ? undefined : assetId,
      itemType: itemType === 'ALL' ? undefined : itemType,
      confidence: confidence === 'ALL' ? undefined : confidence,
      state: triageStateFilter === 'ALL' ? undefined : triageStateFilter,
    }),
    [prefs, reason, minCvss, matchConfidence, assetId, itemType, confidence, triageStateFilter],
  );

  const query = useActionablePage({ page, size, ...filters });

  // A new page/filter combination invalidates whatever was selected against the old one.
  useEffect(() => {
    setRowSelection({});
  }, [page, size, filters]);

  const selectedIds = useMemo(
    () => Object.keys(rowSelection).filter((id) => rowSelection[id]),
    [rowSelection],
  );

  const bulkPatch = useBulkTriagePatch();

  const handleApplyBulk = async () => {
    if (selectedIds.length === 0) return;
    const patch: BulkTriagePatchPayload = { ids: selectedIds };
    if (bulkState !== NO_CHANGE) patch.state = bulkState;
    // No bulk "unassign": the backend has no way to clear an assignee through
    // this endpoint (a null/omitted assigneeId both mean "leave unchanged"),
    // so this select only ever assigns to a real user.
    if (bulkAssigneeId !== NO_CHANGE) patch.assigneeId = bulkAssigneeId;

    if (patch.state === undefined && patch.assigneeId === undefined) {
      toast.error('Pick a state or an assignee to apply.');
      return;
    }

    try {
      const result = await bulkPatch.mutateAsync(patch);
      toast.success(`Updated ${result.updated} item${result.updated === 1 ? '' : 's'}.`);
      setRowSelection({});
      setBulkState(NO_CHANGE);
      setBulkAssigneeId(NO_CHANGE);
    } catch {
      toast.error('Failed to apply the bulk update.');
    }
  };

  useEffect(() => {
    if (query.isError) toast.error('Failed to load actionable items.');
  }, [query.isError]);

  const columns = useMemo(() => actionableColumns(), []);
  const rows = query.data?.content ?? [];
  const showInlineError = query.isError && !query.data;

  const patchPrefs = (patch: Partial<ActionableTogglePrefs>) => {
    setPrefs((prev) => ({ ...prev, ...patch }));
    setPage(0);
  };

  const handleRefresh = async () => {
    const result = await query.refetch();
    if (!result.error) toast.success('Actionable items updated');
  };

  return (
    <TooltipProvider delayDuration={150}>
      <div className="flex flex-col gap-6">
        <ListPageHeader
          title="Actionable Items"
          subtitle="Vulnerabilities that clear the funnel: KEV-listed or high EPSS, ranked by exploitation probability."
          actions={
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
          }
        />

        <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border border-border bg-card p-3">
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <Switch
              checked={prefs.onlyWithFix}
              onCheckedChange={(checked) => patchPrefs({ onlyWithFix: checked })}
              aria-label="Only with a fix"
            />
            Only with a fix
          </label>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <Switch
              checked={prefs.onlyWithExploit}
              onCheckedChange={(checked) => patchPrefs({ onlyWithExploit: checked })}
              aria-label="Only with a known exploit"
            />
            Only with a known exploit
          </label>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Select
              value={reason}
              onValueChange={(v) => {
                setReason(v as ActionableReason | 'ALL');
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[170px]" aria-label="Filter by reason">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REASON_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={minCvss}
              onValueChange={(v) => {
                setMinCvss(v);
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[180px]" aria-label="Filter by minimum CVSS">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MIN_CVSS_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={matchConfidence}
              onValueChange={(v) => {
                setMatchConfidence(v as MatchConfidence | 'ALL');
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[190px]" aria-label="Filter by match confidence">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MATCH_CONFIDENCE_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={assetId}
              onValueChange={(v) => {
                setAssetId(v);
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[180px]" aria-label="Filter by asset">
                <SelectValue placeholder="Any asset" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">Any asset</SelectItem>
                {assetOptions.map((asset) => (
                  <SelectItem key={asset.id} value={asset.id}>
                    {asset.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={itemType}
              onValueChange={(v) => {
                setItemType(v as ActionableItemType | 'ALL');
                // A confidence filter only means anything for compromise rows.
                if (v !== 'COMPROMISE') setConfidence('ALL');
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[210px]" aria-label="Filter by item type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ITEM_TYPE_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {itemType === 'COMPROMISE' && (
              <Select
                value={confidence}
                onValueChange={(v) => {
                  setConfidence(v as CompromiseConfidence | 'ALL');
                  setPage(0);
                }}
              >
                <SelectTrigger className="h-9 w-[170px]" aria-label="Filter by compromise confidence">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONFIDENCE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}

            <Select
              value={triageStateFilter}
              onValueChange={(v) => {
                setTriageStateFilter(v as TriageState | 'ALL');
                setPage(0);
              }}
            >
              <SelectTrigger className="h-9 w-[170px]" aria-label="Filter by triage state">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TRIAGE_FILTER_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {selectedIds.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 p-3">
            <span className="text-sm font-medium text-foreground">
              {selectedIds.length} selected
            </span>

            <Select value={bulkState} onValueChange={(v) => setBulkState(v as TriageState | typeof NO_CHANGE)}>
              <SelectTrigger className="h-9 w-[180px]" aria-label="Bulk set triage state">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_CHANGE}>Leave state as-is</SelectItem>
                {TRIAGE_STATES.map((s) => (
                  <SelectItem key={s} value={s}>
                    Set to {TRIAGE_STATE_LABELS[s]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={bulkAssigneeId} onValueChange={setBulkAssigneeId}>
              <SelectTrigger className="h-9 w-[200px]" aria-label="Bulk set assignee">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_CHANGE}>Leave assignee as-is</SelectItem>
                {users.map((u) => (
                  <SelectItem key={u.id} value={u.id}>
                    Assign to {userLabel(u)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button size="sm" onClick={() => void handleApplyBulk()} disabled={bulkPatch.isPending}>
              {bulkPatch.isPending ? 'Applying…' : 'Apply'}
            </Button>

            <Button
              variant="ghost"
              size="sm"
              className="ml-auto text-muted-foreground"
              onClick={() => setRowSelection({})}
            >
              Clear selection
            </Button>
          </div>
        )}

        {showInlineError ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
            <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
            <p className="text-sm font-medium text-foreground">Unable to load actionable items</p>
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
              onRowClick={(entry) => {
                setSelectedId(entry.id);
                setSelectedItemType(entry.itemType);
                setSelectedTriage(triageSnapshotOf(entry));
              }}
              rowClassName={actionableRowClassName}
              emptyMessage="Nothing actionable right now. Ingest KEV / EPSS and scan an SBOM to populate the funnel."
              enableRowSelection
              rowSelection={rowSelection}
              onRowSelectionChange={setRowSelection}
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

        <ActionableDetailPanel
          id={selectedId}
          itemType={selectedItemType}
          initialTriage={selectedTriage}
          onOpenChange={(open) => {
            if (!open) {
              setSelectedId(null);
              setSelectedItemType(null);
              setSelectedTriage(null);
            }
          }}
          onOpenAsset={(id) => setSelectedAssetId(id)}
        />

        <AssetDetailPanel
          id={selectedAssetId}
          onOpenChange={(open) => {
            if (!open) setSelectedAssetId(null);
          }}
        />
      </div>
    </TooltipProvider>
  );
}
