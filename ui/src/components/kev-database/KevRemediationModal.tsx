import { CalendarClock, Copy, Wrench } from 'lucide-react';
import { toast } from 'sonner';

import type { KEV } from '@/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { formatLongDate } from '@/lib/format';

interface KevRemediationModalProps {
  /** The selected entry, or `null` when the dialog is closed. */
  entry: KEV | null;
  onOpenChange: (open: boolean) => void;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 text-xs font-bold uppercase tracking-wide text-muted-foreground">
        {title}
      </h3>
      {children}
    </div>
  );
}

/**
 * Remediation-strategy dialog for a single KEV entry — ports the Angular
 * `KevRemediationModalComponent`: CISA action deadline, overview, the prominent
 * "Required Action" block, and optional analyst notes, plus a copy-actions button.
 */
export function KevRemediationModal({ entry, onOpenChange }: KevRemediationModalProps) {
  const copyActions = () => {
    if (!entry?.requiredActions) return;
    void navigator.clipboard?.writeText(entry.requiredActions);
    toast.success('Remediation steps copied to clipboard');
  };

  return (
    <Dialog open={entry != null} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        {entry && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Wrench className="h-5 w-5 text-primary" aria-hidden="true" />
                Remediation Strategy: <span className="font-mono">{entry.cveId}</span>
              </DialogTitle>
              <DialogDescription>{entry.name}</DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-5">
              <div className="flex items-center gap-3 rounded-lg bg-severity-medium/10 p-3 text-severity-medium">
                <CalendarClock className="h-6 w-6 shrink-0" aria-hidden="true" />
                <div>
                  <div className="text-xs font-bold uppercase tracking-wide">
                    CISA Federal Action Deadline
                  </div>
                  <div className="text-lg font-semibold text-foreground">
                    {formatLongDate(entry.dueDate)}
                  </div>
                </div>
              </div>

              <Section title="Vulnerability Overview">
                <p className="text-sm text-foreground">
                  {entry.description || 'No description provided.'}
                </p>
              </Section>

              <Section title="Required Action">
                <div className="rounded border-l-4 border-primary bg-muted/50 p-3">
                  <p className="text-sm font-medium text-foreground">
                    {entry.requiredActions || 'No required actions listed.'}
                  </p>
                </div>
              </Section>

              {entry.notes && (
                <Section title="Analyst Notes">
                  <p className="text-sm italic text-muted-foreground">&ldquo;{entry.notes}&rdquo;</p>
                </Section>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Close
              </Button>
              <Button onClick={copyActions} disabled={!entry.requiredActions}>
                <Copy className="h-4 w-4" />
                Copy Actions
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
