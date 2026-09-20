import type { ReactNode } from 'react';
import { ExternalLink, Info, Loader2, ShieldAlert } from 'lucide-react';

import { useActionableDetail, useCompromiseFindingDetail } from '@/api/queries';
import type { ActionableDetail, ActionableItemType, CompromiseFinding } from '@/api/types';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { EM_DASH, formatDate, formatDateTime, formatPercent, formatPercentile } from '@/lib/format';
import { cn } from '@/lib/utils';

import {
  componentLabel,
  COMPROMISE_TYPE_LABELS,
  EXPLOIT_MATURITY_LABELS,
  isKevOverdue,
  REASON_LABELS,
} from './actionable.helpers';
import { CompromiseConfidenceBadge } from './CompromiseConfidenceBadge';
import { ExploitBadge } from './ExploitBadge';
import { FixBadge } from './FixBadge';
import { MaliciousBadge } from './MaliciousBadge';
import { MatchConfidenceBadge } from './MatchConfidenceBadge';

interface ActionableDetailPanelProps {
  /** Alert id (VULNERABILITY) or finding id (COMPROMISE) to load, or `null` when closed. */
  id: string | null;
  /**
   * Which detail endpoint `id` addresses (Phase 6) — `GET /actionable/:id` for
   * a `vulnerability_alert`, `GET /compromise/:id` for a `compromise_finding`.
   * `null`/`VULNERABILITY` both resolve to the pre-Phase-6 endpoint, so every
   * existing caller (e.g. a deep link with no row context) keeps working.
   */
  itemType?: ActionableItemType | null;
  onOpenChange: (open: boolean) => void;
  /**
   * Called when the user activates an asset reference in "Affected
   * components" (Phase 4). Renders those references as plain text when
   * omitted — used by `ActionableView` (which also owns an `AssetDetailPanel`)
   * but not required by every caller.
   */
  onOpenAsset?: (assetId: string) => void;
}

/** `CompromiseFinding.referencesJson` is a raw feed array, unparsed on the wire. */
function parseReferences(json: string | null): { url: string; type?: string }[] {
  if (!json) return [];
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r): r is { url: string; type?: string } =>
        typeof r === 'object' && r != null && typeof (r as { url?: unknown }).url === 'string',
    );
  } catch {
    return [];
  }
}

function CompromiseBody({
  finding,
  onOpenAsset,
}: {
  finding: CompromiseFinding;
  onOpenAsset?: (assetId: string) => void;
}) {
  const references = parseReferences(finding.referencesJson);

  return (
    <div className="mt-4 flex flex-col gap-6 text-sm">
      {finding.agedAt && (
        <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-muted-foreground">
          <Info className="h-4 w-4 shrink-0" aria-hidden="true" />
          Demoted to Investigate on {formatDateTime(finding.agedAt)} — this indicator's evidence
          has gone stale.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <MaliciousBadge />
        <CompromiseConfidenceBadge confidence={finding.confidence} />
        <span className="rounded-full border border-border px-2 py-0.5 text-xs font-medium text-muted-foreground">
          {COMPROMISE_TYPE_LABELS[finding.type] ?? finding.type}
        </span>
      </div>

      {finding.summary && <p className="whitespace-pre-line text-sm text-foreground">{finding.summary}</p>}

      <div className="grid grid-cols-1 gap-x-8 gap-y-6 sm:grid-cols-2">
        <Section title="Indicator">
          <Row label="Source" value={finding.source} />
          <Row label="IOC id" value={<span className="font-mono text-xs">{finding.iocId}</span>} />
          <Row label="Matched on" value={<span className="font-mono text-xs">{finding.matchedOn}</span>} />
          {finding.origins && <Row label="Reported by" value={finding.origins} />}
        </Section>

        <Section title="Freshness">
          <Row label="First seen" value={formatDateTime(finding.iocFirstSeen)} />
          <Row label="Last seen" value={formatDateTime(finding.iocLastSeen)} />
          {finding.iocConfidence != null && (
            <Row label="Feed confidence" value={formatPercent(finding.iocConfidence, 0)} />
          )}
          <Row label="Added to funnel" value={formatDateTime(finding.createdAt)} />
        </Section>
      </div>

      <Section title="Matched component">
        <div className="rounded border border-border bg-card p-2">
          <div className="font-mono text-xs text-foreground" title={finding.componentPurl ?? undefined}>
            {componentLabel(finding.componentName, finding.componentVersion)}
          </div>
          {finding.assetName ? (
            onOpenAsset && finding.assetId ? (
              <button
                type="button"
                onClick={() => onOpenAsset(finding.assetId!)}
                className="text-xs text-primary hover:underline"
              >
                {finding.assetName} (asset)
              </button>
            ) : (
              <div className="text-xs text-muted-foreground">{finding.assetName} (asset)</div>
            )
          ) : (
            finding.productName && (
              <div className="text-xs text-muted-foreground">{finding.productName}</div>
            )
          )}
        </div>
      </Section>

      {finding.details && (
        <Section title="Analyst write-up">
          <p className="whitespace-pre-line text-sm text-foreground">{finding.details}</p>
        </Section>
      )}

      <Section title="References">
        {references.length === 0 ? (
          <p className="text-sm text-muted-foreground">No references listed.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {references.map((ref, i) => (
              <li key={`${ref.url}-${i}`} className="min-w-0">
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 text-primary hover:underline"
                  title={ref.url}
                >
                  <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span className="truncate">{ref.type || ref.url}</span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
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

function Body({
  detail,
  onOpenAsset,
}: {
  detail: ActionableDetail;
  onOpenAsset?: (assetId: string) => void;
}) {
  const { cve, kev, epss } = detail;
  const cvss = detail.cvssScore ?? cve.cvssScore;

  return (
    <div className="mt-4 flex flex-col gap-6 text-sm">
      {detail.lifecycleState === 'AUTO_RESOLVED' && (
        <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-muted-foreground">
          <Info className="h-4 w-4 shrink-0" aria-hidden="true" />
          Auto-resolved — no longer matches your current scan.
        </div>
      )}

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
            value={
              <FixBadge
                state={detail.fixState}
                fixedVersions={detail.fixedVersions}
                fixSource={detail.fixSource}
              />
            }
          />
          {detail.fixSource && <Row label="Fix source" value={detail.fixSource} />}
          <Row
            label="Match confidence"
            value={
              detail.matchConfidence ? (
                <MatchConfidenceBadge confidence={detail.matchConfidence} />
              ) : (
                EM_DASH
              )
            }
          />
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
                {c.assetName ? (
                  onOpenAsset ? (
                    <button
                      type="button"
                      onClick={() => onOpenAsset(c.assetId!)}
                      className="text-xs text-primary hover:underline"
                    >
                      {c.assetName} (asset)
                    </button>
                  ) : (
                    <div className="text-xs text-muted-foreground">{c.assetName} (asset)</div>
                  )
                ) : (
                  c.productName && (
                    <div className="text-xs text-muted-foreground">{c.productName}</div>
                  )
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
export function ActionableDetailPanel({
  id,
  itemType,
  onOpenChange,
  onOpenAsset,
}: ActionableDetailPanelProps) {
  const isCompromise = itemType === 'COMPROMISE';
  // Both hooks are called on every render (rules of hooks) — only the one
  // matching `itemType` is ever enabled, the other's `id` stays undefined.
  const alertQuery = useActionableDetail(!isCompromise ? (id ?? undefined) : undefined);
  const findingQuery = useCompromiseFindingDetail(isCompromise ? (id ?? undefined) : undefined);
  const query = isCompromise ? findingQuery : alertQuery;

  const title = isCompromise ? (findingQuery.data?.iocId ?? 'Compromise finding') : (alertQuery.data?.cve.id ?? 'Actionable item');
  const description = isCompromise
    ? 'A known-bad artefact matched in your estate — what it is and where it was found.'
    : 'Why this made the funnel, and what to do about it.';

  return (
    <Sheet open={id != null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="font-mono">{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
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
              {isCompromise
                ? 'Could not load this finding.'
                : 'Could not load this item. It may have been re-evaluated out of the funnel.'}
            </p>
          </div>
        ) : isCompromise ? (
          <CompromiseBody finding={findingQuery.data!} onOpenAsset={onOpenAsset} />
        ) : (
          <Body detail={alertQuery.data!} onOpenAsset={onOpenAsset} />
        )}
      </SheetContent>
    </Sheet>
  );
}
