import { Wrench } from 'lucide-react';

import type { SBOM } from '@/api/types';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatDateTime, formatInteger } from '@/lib/format';
import { cn } from '@/lib/utils';

import {
  countActionableAlerts,
  countAlerts,
  sbomStatusLabel,
  sbomsByRecency,
} from './product.derive';
import type { DerivedProduct, SbomStatusDisplay } from './product.types';

const STATUS_STYLES: Record<SbomStatusDisplay, string> = {
  Scanning: 'bg-severity-medium/10 text-severity-medium',
  Complete: 'bg-severity-low/10 text-severity-low',
  Failed: 'bg-destructive/10 text-destructive',
  Unknown: 'bg-muted text-muted-foreground',
};

interface SbomHistoryModalProps {
  product: DerivedProduct | null;
  onOpenChange: (open: boolean) => void;
}

function ToolList({ tools }: { tools: SBOM['tools'] }) {
  if (!tools?.length) {
    return <span className="text-xs italic text-muted-foreground">No tool metadata</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {tools.map((tool, index) => (
        <span
          key={tool.id ?? `${tool.name}-${index}`}
          className="inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground"
          title={[tool.group, tool.name, tool.version, tool.type].filter(Boolean).join(' · ')}
        >
          <Wrench className="h-3 w-3" aria-hidden="true" />
          {tool.name}
          {tool.version ? ` v${tool.version}` : ''}
        </span>
      ))}
    </div>
  );
}

/**
 * Read-only SBOM version history for a product — newest upload first. Ports the
 * Angular `SbomHistoryModalComponent` table into a scrollable card list.
 */
export function SbomHistoryModal({ product, onOpenChange }: SbomHistoryModalProps) {
  const sboms = product ? sbomsByRecency(product) : [];

  return (
    <Dialog open={product != null} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>SBOM Version History</DialogTitle>
          <DialogDescription>
            {product ? (
              <>
                Every SBOM uploaded for <span className="font-medium">{product.name}</span>.
              </>
            ) : null}
          </DialogDescription>
        </DialogHeader>

        {sboms.length === 0 ? (
          <p className="py-10 text-center text-sm text-muted-foreground">
            No SBOMs uploaded yet.
          </p>
        ) : (
          <ScrollArea className="-mx-2 max-h-[60vh] px-2">
            <ul className="flex flex-col gap-3">
              {sboms.map((sbom) => {
                const status = sbomStatusLabel(sbom.status);
                const total = countAlerts(sbom);
                const actionable = countActionableAlerts(sbom);
                return (
                  <li key={sbom.id} className="rounded-lg border border-border p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-foreground">
                          {sbom.productVersion || 'Unknown'}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">
                          doc v{sbom.version} · {sbom.id.slice(0, 8)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {sbom.active && (
                          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">
                            Active
                          </span>
                        )}
                        <span
                          className={cn(
                            'rounded-full px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
                            STATUS_STYLES[status],
                          )}
                        >
                          {status}
                        </span>
                      </div>
                    </div>

                    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      <span>
                        {sbom.format || 'CycloneDX'}
                        {sbom.specVersion ? ` ${sbom.specVersion}` : ''}
                      </span>
                      <span>Uploaded {formatDateTime(sbom.uploadDate)}</span>
                      <span>
                        <span className="font-semibold text-foreground">
                          {formatInteger(total)}
                        </span>{' '}
                        findings
                      </span>
                      <span
                        className={cn(
                          actionable > 0 ? 'text-destructive' : undefined,
                        )}
                      >
                        <span className="font-semibold">{formatInteger(actionable)}</span> actionable
                      </span>
                    </div>

                    <div className="mt-2">
                      <ToolList tools={sbom.tools} />
                    </div>
                  </li>
                );
              })}
            </ul>
          </ScrollArea>
        )}
      </DialogContent>
    </Dialog>
  );
}
