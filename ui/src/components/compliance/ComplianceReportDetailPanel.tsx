import { useState, type ReactNode } from 'react';
import { ExternalLink, Loader2, RefreshCw, ShieldAlert } from 'lucide-react';

import {
  useComplianceMisconfigurations,
  useComplianceReportDetail,
  useRescanComplianceReport,
} from '@/api/queries';
import type {
  ComplianceMisconfiguration,
  ComplianceReportDetail,
  ComplianceStatus,
} from '@/api/types';
import { actionableColumns } from '@/components/actionable/actionable.columns';
import { ActionableDetailPanel } from '@/components/actionable/ActionableDetailPanel';
import { DataTable } from '@/components/common/DataTable';
import { Pagination } from '@/components/common/Pagination';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { JobStatusBadge } from '@/components/jobs/JobStatusBadge';
import { useIngestJob } from '@/components/jobs/useIngestJob';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { EM_DASH, formatDateTime, formatRelativeDate } from '@/lib/format';
import { cn } from '@/lib/utils';

import {
  ComplianceCheckStatusBadge,
  ComplianceReportStatusBadge,
  ControlBreakdownBar,
  ControlBreakdownCounts,
} from './compliance.helpers';

interface ComplianceReportDetailPanelProps {
  /** Report id to load, or `null` when the panel is closed. */
  id: string | null;
  onOpenChange: (open: boolean) => void;
  /**
   * Called when the user activates the audited asset's name. Renders it as
   * plain text when omitted — mirrors `ActionableDetailPanel`'s `onOpenAsset`.
   */
  onOpenAsset?: (assetId: string) => void;
}

const STATUS_OPTIONS: { value: ComplianceStatus | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'Any status' },
  { value: 'FAIL', label: 'Failed only' },
  { value: 'PASS', label: 'Passed only' },
  { value: 'SKIP', label: 'Skipped only' },
];

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

function MisconfigCard({
  controlId,
  checkId,
  avdId,
  title,
  description,
  message,
  resolution,
  severity,
  status,
  target,
  primaryUrl,
}: ComplianceMisconfiguration) {
  return (
    <li className="rounded border border-border bg-card p-3">
      <div className="flex flex-wrap items-center gap-2">
        <ComplianceCheckStatusBadge status={status} />
        {severity && <SeverityBadge severity={severity} />}
        <span className="font-mono text-xs text-muted-foreground">
          {avdId ?? checkId ?? controlId ?? EM_DASH}
        </span>
      </div>
      <p className="mt-1.5 text-sm font-semibold text-foreground">
        {title ?? message ?? 'Untitled check'}
      </p>
      {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      {target && (
        <p className="mt-1 font-mono text-xs text-muted-foreground" title="Target">
          {target}
        </p>
      )}
      {resolution && (
        <div className="mt-2 rounded border-l-4 border-primary bg-muted/50 p-2">
          <p className="text-xs font-bold uppercase tracking-wide text-primary">Remediation</p>
          <p className="mt-0.5 text-sm text-foreground">{resolution}</p>
        </div>
      )}
      {primaryUrl && (
        <a
          href={primaryUrl}
          target="_blank"
          rel="noreferrer"
          className="mt-2 flex w-fit items-center gap-1.5 text-xs text-primary hover:underline"
        >
          <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          {primaryUrl}
        </a>
      )}
    </li>
  );
}

function Body({
  id,
  detail,
  onOpenAsset,
}: {
  id: string;
  detail: ComplianceReportDetail;
  onOpenAsset?: (assetId: string) => void;
}) {
  const [misconfigPage, setMisconfigPage] = useState(0);
  const [misconfigStatus, setMisconfigStatus] = useState<ComplianceStatus | 'ALL'>('ALL');
  const [selectedActionableId, setSelectedActionableId] = useState<string | null>(null);

  const misconfigQuery = useComplianceMisconfigurations(id, {
    page: misconfigPage,
    size: 10,
    status: misconfigStatus === 'ALL' ? undefined : misconfigStatus,
  });

  const rescan = useRescanComplianceReport();
  const {
    start,
    running,
    status: jobStatus,
  } = useIngestJob({
    ingest: () => rescan.mutateAsync(id),
    startMessage: 'Re-scanning report…',
    successMessage: 'Report re-scanned.',
    errorMessage: 'Re-scan failed. Check the backend and try again.',
  });

  const actionColumns = actionableColumns();
  const actionableRows = detail.actionableItems.content;
  const misconfigRows = misconfigQuery.data?.content ?? [];

  return (
    <div className="mt-4 flex flex-col gap-6 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <ComplianceReportStatusBadge status={detail.status} />
        {detail.assetName &&
          (onOpenAsset ? (
            <button
              type="button"
              className="font-mono text-xs text-primary hover:underline"
              onClick={() => onOpenAsset(detail.assetId!)}
            >
              {detail.assetName}
            </button>
          ) : (
            <span className="font-mono text-xs text-muted-foreground">{detail.assetName}</span>
          ))}
        <Button
          variant="outline"
          size="sm"
          className="ml-auto"
          onClick={() => void start()}
          disabled={running}
        >
          {running ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Re-scan
        </Button>
      </div>

      {jobStatus && (
        <div className="flex items-center gap-2 rounded-md border border-border bg-muted/50 p-2 text-xs">
          <JobStatusBadge status={jobStatus} />
          <span className="text-muted-foreground">Re-scanning against the current funnel…</span>
        </div>
      )}

      <Section title="Control breakdown">
        <div className="flex flex-col gap-3">
          <ControlBreakdownCounts {...detail} />
          <ControlBreakdownBar {...detail} className="h-3" />
        </div>
      </Section>

      <Section title="Report">
        <Row label="Benchmark" value={detail.benchmarkId ?? EM_DASH} />
        <Row label="Version" value={detail.version ?? EM_DASH} />
        <Row label="Total controls" value={detail.totalControls} />
        <Row label="Scanned" value={formatRelativeDate(detail.scannedAt)} />
        <Row label="Created" value={formatDateTime(detail.createdAt)} />
      </Section>

      {detail.description && (
        <Section title="Description">
          <p className="whitespace-pre-line text-sm text-foreground">{detail.description}</p>
        </Section>
      )}

      <Section title={`Misconfigurations (${misconfigQuery.data?.totalElements ?? 0})`}>
        <div className="mb-3 flex items-center justify-end">
          <Select
            value={misconfigStatus}
            onValueChange={(v) => {
              setMisconfigStatus(v as ComplianceStatus | 'ALL');
              setMisconfigPage(0);
            }}
          >
            <SelectTrigger className="h-8 w-[160px] text-xs" aria-label="Filter by check status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {misconfigRows.length === 0 ? (
          <p className="text-sm text-muted-foreground">No checks match this filter.</p>
        ) : (
          <ul className={cn('flex flex-col gap-2', misconfigQuery.isFetching && 'opacity-60')}>
            {misconfigRows.map((m) => (
              <MisconfigCard key={m.id} {...m} />
            ))}
          </ul>
        )}

        {misconfigQuery.data && misconfigQuery.data.totalPages > 1 && (
          <Pagination
            className="mt-3"
            page={misconfigQuery.data.number}
            size={misconfigQuery.data.size}
            totalElements={misconfigQuery.data.totalElements}
            totalPages={misconfigQuery.data.totalPages}
            onPageChange={setMisconfigPage}
          />
        )}
      </Section>

      <Section title={`Actionable items (${detail.actionableItems.totalElements})`}>
        {actionableRows.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No vulnerability alerts from this report's audited asset right now.
          </p>
        ) : (
          <DataTable
            columns={actionColumns}
            data={actionableRows}
            getRowId={(entry) => entry.id}
            onRowClick={(entry) => setSelectedActionableId(entry.id)}
            emptyMessage="No vulnerability alerts from this report's audited asset right now."
          />
        )}
      </Section>

      <ActionableDetailPanel
        id={selectedActionableId}
        onOpenChange={(open) => {
          if (!open) setSelectedActionableId(null);
        }}
      />
    </div>
  );
}

/**
 * Right-hand detail sheet for one compliance report, driven by
 * {@link useComplianceReportDetail}. Mirrors `AssetDetailPanel`'s mechanics:
 * the control breakdown up top, a paged/filterable misconfiguration list with
 * remediation text, then the audited asset's actionable items reusing
 * `actionableColumns()` and `ActionableDetailPanel` — the exact same
 * `ActionableItem` shape, so there is nothing report-specific to render
 * differently.
 */
export function ComplianceReportDetailPanel({
  id,
  onOpenChange,
  onOpenAsset,
}: ComplianceReportDetailPanelProps) {
  const query = useComplianceReportDetail(id ?? undefined);

  return (
    <Sheet open={id != null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="font-mono">
            {query.data?.title ?? query.data?.benchmarkId ?? 'Compliance report'}
          </SheetTitle>
          <SheetDescription>
            Control pass/fail breakdown, misconfigurations with remediation, and the vulnerability
            alerts this audit raised.
          </SheetDescription>
        </SheetHeader>

        {query.isPending ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">Loading report…</p>
          </div>
        ) : query.isError || !query.data ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">Could not load this report.</p>
          </div>
        ) : (
          <Body id={id!} detail={query.data} onOpenAsset={onOpenAsset} />
        )}
      </SheetContent>
    </Sheet>
  );
}
