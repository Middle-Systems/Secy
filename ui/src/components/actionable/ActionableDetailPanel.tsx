import type { ReactNode } from 'react';
import { ExternalLink, Loader2, ShieldAlert } from 'lucide-react';

import { useActionableDetail } from '@/api/queries';
import type { ActionableDetail } from '@/api/types';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { EM_DASH, formatDate, formatPercent, formatPercentile } from '@/lib/format';
import { cn } from '@/lib/utils';

import {
  componentLabel,
  EXPLOIT_MATURITY_LABELS,
  isKevOverdue,
  REASON_LABELS,
} from './actionable.helpers';
import { ExploitBadge } from './ExploitBadge';
import { FixBadge } from './FixBadge';

interface ActionableDetailPanelProps {
  /** Alert id to load, or `null` when the panel is closed. */
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

function orDash(value: string | null | undefined): string {
  return value && value.trim() ? value : EM_DASH;
}

function Body({ detail }: { detail: ActionableDetail }) {
  const { cve, kev, epss } = detail;
  const cvss = detail.cvssScore ?? cve.cvssScore;

  return (
    <div className="mt-4 flex flex-col gap-6 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={cve.baseSeverity} score={cvss ?? undefined} />
        {cvss != null && (
          <span className="text-xs text-muted-foreground">CVSS {cvss.toFixed(1)}</span>
        )}
        {detail.actionableReason && (
          <span className="rounded-full border border-border px-2 py-0.5 text-xs font-medium text-muted-foreground">
            {REASON_LABELS[detail.actionableReason] ?? detail.actionableReason}
          </span>
        )}
        {!detail.actionable && (
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
            Not currently actionable
          </span>
        )}
      </div>

      {cve.description && (
        <p className="whitespace-pre-line text-sm text-foreground">{cve.description}</p>
      )}

      <div className="grid grid-cols-1 gap-x-8 gap-y-6 sm:grid-cols-2">
        <Section title="Risk signals">
          <Row
            label="EPSS score"
            value={detail.epssScore != null ? formatPercent(detail.epssScore, 1) : EM_DASH}
          />
          <Row label="EPSS percentile" value={formatPercentile(detail.epssPercentile)} />
          <Row
            label="Exploit maturity"
            value={
              detail.exploitMaturity === 'NONE' ? (
                <span className="text-muted-foreground">{EXPLOIT_MATURITY_LABELS.NONE}</span>
              ) : (
                <ExploitBadge maturity={detail.exploitMaturity} />
              )
            }
          />
          <Row
            label="Fix"
            value={<FixBadge state={detail.fixState} fixedVersions={detail.fixedVersions} />}
          />
          {detail.fixSource && <Row label="Fix source" value={detail.fixSource} />}
        </Section>

        <Section title="CVE">
          <Row label="ID" value={<span className="font-mono">{cve.id}</span>} />
          <Row label="Status" value={orDash(cve.vulnStatus)} />
          <Row label="CWE" value={orDash(cve.cwe)} />
          <Row label="Published" value={formatDate(cve.published)} />
          <Row label="Attack vector" value={orDash(cve.accessVector)} />
          <Row label="Added to funnel" value={formatDate(detail.createdAt)} />
        </Section>
      </div>

      {kev && (
        <Section title="CISA KEV">
          <div
            className={cn(
              'mb-2 flex items-center gap-2 rounded-md px-3 py-2 text-xs font-semibold',
              isKevOverdue(kev.dueDate ?? detail.kevDueDate)
                ? 'bg-destructive/10 text-destructive'
                : 'bg-severity-high/10 text-severity-high',
            )}
          >
            <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
            Remediate by {formatDate(kev.dueDate ?? detail.kevDueDate)}
            {isKevOverdue(kev.dueDate ?? detail.kevDueDate) && ' — overdue'}
          </div>
          <Row label="Vendor / product" value={`${kev.vendor} / ${kev.product}`} />
          <Row
            label="Known ransomware use"
            value={orDash(detail.knownRansomwareUse ?? kev.knownRansomwareCampaignUse)}
          />
          {kev.requiredActions && (
            <div className="mt-2 rounded border-l-4 border-primary bg-muted/50 p-3">
              <p className="text-sm text-foreground">{kev.requiredActions}</p>
            </div>
          )}
        </Section>
      )}

      {epss && (
        <Section title="FIRST EPSS">
          <Row label="Probability" value={formatPercent(epss.epss, 2)} />
          <Row label="Percentile" value={formatPercentile(epss.percentile)} />
          <Row label="As of" value={formatDate(epss.date)} />
        </Section>
      )}

      <Section title={`Affected components (${detail.affectedComponents.length})`}>
        {detail.affectedComponents.length === 0 ? (
          <p className="text-sm text-muted-foreground">No component links.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {detail.affectedComponents.map((c) => (
              <li
                key={c.alertId}
                className={cn(
                  'rounded border border-border bg-card p-2',
                  c.alertId === detail.id && 'border-primary',
                )}
              >
                <div className="font-mono text-xs text-foreground" title={c.purl ?? undefined}>
                  {componentLabel(c.name, c.version)}
                </div>
                {c.productName && (
                  <div className="text-xs text-muted-foreground">{c.productName}</div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="References">
        {detail.references.length === 0 ? (
          <p className="text-sm text-muted-foreground">No references listed.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {detail.references.map((ref, i) => (
              <li key={`${ref.url}-${i}`} className="min-w-0">
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 text-primary hover:underline"
                  title={ref.url}
                >
                  <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span className="truncate">{ref.source || ref.url}</span>
                </a>
                {ref.tags && <span className="ml-5 text-xs text-muted-foreground">{ref.tags}</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

/**
 * Right-hand detail sheet for one actionable item, driven by
 * {@link useActionableDetail}. Open state is derived from `id != null`.
 */
export function ActionableDetailPanel({ id, onOpenChange }: ActionableDetailPanelProps) {
  const query = useActionableDetail(id ?? undefined);

  return (
    <Sheet open={id != null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="font-mono">{query.data?.cve.id ?? 'Actionable item'}</SheetTitle>
          <SheetDescription>Why this made the funnel, and what to do about it.</SheetDescription>
        </SheetHeader>

        {query.isPending ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">Loading detail…</p>
          </div>
        ) : query.isError || !query.data ? (
          <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 text-center">
            <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">
              Could not load this item. It may have been re-evaluated out of the funnel.
            </p>
          </div>
        ) : (
          <Body detail={query.data} />
        )}
      </SheetContent>
    </Sheet>
  );
}
