import { useRef, useState } from 'react';
import { FileJson, Loader2, UploadCloud } from 'lucide-react';

import { useProducts, useUploadComplianceReport } from '@/api/queries';
import type { AssetType } from '@/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { JobStatusBadge } from '@/components/jobs/JobStatusBadge';
import { useIngestJob } from '@/components/jobs/useIngestJob';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

interface UploadComplianceReportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface ParsedFile {
  name: string;
  report: unknown;
  /** The document's own artifact/target name, if any — pre-fills the name field. */
  detectedName: string | null;
}

const ASSET_TYPE_OPTIONS: { value: AssetType; label: string }[] = [
  { value: 'CONTAINER_IMAGE', label: 'Container image' },
  { value: 'HOST', label: 'Host' },
  { value: 'SERVICE', label: 'Service' },
];

/**
 * Best-effort shape sniff, mirroring `CisReportParser`'s own two checks —
 * `looksLikeCompliance` / `looksLikeImageScan` — so the UI rejects the same
 * things the backend would, without duplicating its parsing. A UX nicety, not
 * a substitute for server-side validation: the backend is the source of
 * truth and will still 400 a real mismatch.
 *
 * A `trivy --compliance <spec> -f json` document is
 * `{ ID, Title, Results: [{ results: [{ Target, misconfigurations, vulnerabilities }] }] }`.
 * A plain `trivy image` vulnerability report shares the top-level `Results`
 * array but has no `ID`/`Title` and instead carries `SchemaVersion` or
 * `ArtifactType` — that shape belongs on the Infrastructure "Scan asset" modal.
 */
function sniffCompliance(doc: unknown): { ok: true; detectedName: string | null } | { ok: false } {
  if (doc == null || typeof doc !== 'object') return { ok: false };
  const record = doc as Record<string, unknown>;
  if (!Array.isArray(record.Results)) return { ok: false };

  const looksLikeImageScan =
    typeof record.ID !== 'string' &&
    (typeof record.SchemaVersion === 'number' || typeof record.ArtifactType === 'string');
  if (looksLikeImageScan) return { ok: false };

  const looksLikeCompliance = typeof record.ID === 'string' && typeof record.Title === 'string';
  if (!looksLikeCompliance) return { ok: false };

  const firstControl = record.Results[0] as Record<string, unknown> | undefined;
  const firstTarget = Array.isArray(firstControl?.results)
    ? (firstControl!.results as Record<string, unknown>[])[0]
    : undefined;
  const detectedName =
    typeof record.ArtifactName === 'string'
      ? record.ArtifactName
      : typeof firstTarget?.Target === 'string'
        ? (firstTarget.Target as string)
        : null;

  return { ok: true, detectedName };
}

/**
 * "Upload compliance report" dialog — reads a `.json` CIS/Trivy compliance
 * report locally, sniffs its shape, then posts through
 * {@link useUploadComplianceReport}.
 *
 * Mirrors `ScanAssetModal`'s mechanics closely: the POST answers with a `Job`
 * to poll, so this drives the same `useIngestJob` enqueue → poll → settle
 * lifecycle — progress badge while running, success toast + close, and on
 * failure the dialog stays open with the file still selected so the user can
 * retry without re-picking it.
 */
export function UploadComplianceReportModal({
  open,
  onOpenChange,
}: UploadComplianceReportModalProps) {
  const uploadReport = useUploadComplianceReport();
  const products = useProducts();
  const inputRef = useRef<HTMLInputElement>(null);

  const [parsed, setParsed] = useState<ParsedFile | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [type, setType] = useState<AssetType>('CONTAINER_IMAGE');
  const [productId, setProductId] = useState<string>('NONE');

  const { start, running, enqueuing, status, message } = useIngestJob({
    ingest: () =>
      uploadReport.mutateAsync({
        report: parsed!.report,
        name: name.trim() || undefined,
        type,
        productId: productId === 'NONE' ? undefined : productId,
      }),
    startMessage: 'Uploading compliance report…',
    successMessage: 'Compliance report ingested and correlated.',
    errorMessage:
      'Compliance report upload failed. Check the file and the backend, then try again.',
    onIngested: () => handleOpenChange(false),
  });

  const reset = () => {
    setParsed(null);
    setFileError(null);
    setName('');
    setType('CONTAINER_IMAGE');
    setProductId('NONE');
    if (inputRef.current) inputRef.current.value = '';
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const handleFile = async (file: File | undefined) => {
    setParsed(null);
    setFileError(null);
    if (!file) return;

    let doc: unknown;
    try {
      doc = JSON.parse(await file.text());
    } catch {
      setFileError('That file is not valid JSON.');
      return;
    }

    const sniff = sniffCompliance(doc);
    if (!sniff.ok) {
      setFileError(
        "This does not look like a Trivy compliance report (expected top-level 'ID' and 'Title' fields alongside a 'Results' array, as produced by `trivy ... --compliance <spec> -f json`).",
      );
      return;
    }
    setParsed({ name: file.name, report: doc, detectedName: sniff.detectedName });
    if (!name && sniff.detectedName) setName(sniff.detectedName);
  };

  const upload = () => {
    if (!parsed) return;
    void start();
  };

  const nameRequired = Boolean(parsed) && !parsed?.detectedName;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload compliance report</DialogTitle>
          <DialogDescription>
            Upload a `trivy --compliance` JSON report to record a benchmark audit and correlate its
            vulnerability findings against the funnel.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="compliance-file">Compliance report (JSON)</Label>
            <label
              htmlFor="compliance-file"
              className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground hover:border-primary hover:text-foreground"
            >
              {parsed ? (
                <>
                  <FileJson className="h-7 w-7 text-primary" aria-hidden="true" />
                  <span className="font-medium text-foreground">{parsed.name}</span>
                  <span className="text-xs">Click to choose a different file</span>
                </>
              ) : (
                <>
                  <UploadCloud className="h-7 w-7 text-primary" aria-hidden="true" />
                  <span>Click to select a Trivy compliance JSON report</span>
                </>
              )}
            </label>
            <Input
              ref={inputRef}
              id="compliance-file"
              type="file"
              accept=".json,application/json"
              className="sr-only"
              disabled={running}
              onChange={(event) => void handleFile(event.target.files?.[0])}
            />
            {fileError && <p className="text-sm font-medium text-destructive">{fileError}</p>}
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="compliance-asset-type-select">Asset type</Label>
            <Select value={type} onValueChange={(v) => setType(v as AssetType)}>
              <SelectTrigger id="compliance-asset-type-select" disabled={running}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ASSET_TYPE_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="compliance-asset-name">
              Asset name{nameRequired ? '' : ' (optional)'}
            </Label>
            <Input
              id="compliance-asset-name"
              placeholder="e.g. acme/api:1.4.2"
              value={name}
              onChange={(event) => setName(event.target.value)}
              disabled={running}
            />
            <p className="text-xs text-muted-foreground">
              {nameRequired
                ? 'This report does not name what it audited — required for this file.'
                : "Defaults to the report's own artifact name when left blank."}
            </p>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="compliance-product-select">Linked product (optional)</Label>
            <Select value={productId} onValueChange={setProductId}>
              <SelectTrigger id="compliance-product-select" disabled={running}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="NONE">No linked product</SelectItem>
                {(products.data ?? []).map((product) => (
                  <SelectItem key={product.id} value={product.id}>
                    {product.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {status && (
            <div className="flex items-center gap-2 rounded-md border border-border bg-muted/50 p-3 text-sm">
              <JobStatusBadge status={status} />
              <span className="text-muted-foreground">
                {status === 'FAILED' || status === 'CANCELLED'
                  ? (message ??
                    'The upload did not finish. You can retry without re-selecting the file.')
                  : (message ?? 'Processing…')}
              </span>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => handleOpenChange(false)}
            disabled={enqueuing}
          >
            {running ? 'Close' : 'Cancel'}
          </Button>
          <Button
            type="button"
            onClick={upload}
            disabled={!parsed || running || (nameRequired && !name.trim())}
          >
            {running && <Loader2 className="h-4 w-4 animate-spin" />}
            {running ? 'Uploading…' : 'Upload report'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
