import { useRef, useState } from 'react';
import { FileJson, Loader2, UploadCloud } from 'lucide-react';

import { useUploadSbom } from '@/api/queries';
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
import { formatInteger } from '@/lib/format';

import type { DerivedProduct } from './product.types';

interface UploadSbomModalProps {
  product: DerivedProduct | null;
  onOpenChange: (open: boolean) => void;
}

interface ParsedFile {
  name: string;
  sbom: unknown;
}

/**
 * Loose format check — enough to reject an obviously wrong file before it ever reaches the
 * network. Deliberately not stricter than the backend: `SbomParser` is the source of truth (it
 * checks `bomFormat` / `spdxVersion` and rejects an unsupported SPDX revision), and will 400 a
 * document this lets through. This is just a UX nicety so a client sees the problem before
 * uploading, not a substitute for that validation.
 */
function looksLikeSupportedSbom(doc: unknown): boolean {
  if (doc == null || typeof doc !== 'object') return false;
  const record = doc as Record<string, unknown>;
  const bomFormat = typeof record.bomFormat === 'string' ? record.bomFormat.toLowerCase() : '';
  if (bomFormat === 'cyclonedx' || Array.isArray(record.components)) return true;
  return typeof record.spdxVersion === 'string' && record.spdxVersion.trim().length > 0;
}

/**
 * "Upload SBOM" dialog — reads a `.json` file locally, parses it, sanity-checks that it looks like
 * CycloneDX or SPDX, then posts through `useUploadSbom`.
 *
 * The upload itself is a background job now (Phase 3): the POST answers with a `Job` to poll, not
 * the finished `SBOM`, so this tracks it with the same `useIngestJob` enqueue → poll → settle
 * lifecycle `IngestButton` / the CVE view's `IngestModal` use — showing QUEUED/RUNNING progress
 * (with the live component count once the job reports one) and closing only once it actually
 * SUCCEEDED. On FAILED/CANCELLED the dialog stays open with the parsed file still in state, so the
 * user can retry with one click rather than re-picking the file.
 */
export function UploadSbomModal({ product, onOpenChange }: UploadSbomModalProps) {
  const uploadSbom = useUploadSbom();
  const inputRef = useRef<HTMLInputElement>(null);
  const [productVersion, setProductVersion] = useState('');
  const [parsed, setParsed] = useState<ParsedFile | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const { start, running, enqueuing, status, itemsProcessed, message } = useIngestJob({
    ingest: () =>
      uploadSbom.mutateAsync({
        productId: product!.id,
        sbom: parsed!.sbom,
        productVersion: productVersion.trim() || undefined,
      }),
    startMessage: 'Uploading SBOM…',
    successMessage: 'SBOM ingested and scanned.',
    errorMessage: 'SBOM upload failed. Check the file and the backend, then try again.',
    onIngested: () => handleOpenChange(false),
  });

  const reset = () => {
    setProductVersion('');
    setParsed(null);
    setFileError(null);
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
    if (!looksLikeSupportedSbom(doc)) {
      setFileError(
        'This does not look like a CycloneDX or SPDX SBOM (expected `bomFormat: "CycloneDX"`, a `components` array, or `spdxVersion`).',
      );
      return;
    }
    setParsed({ name: file.name, sbom: doc });
  };

  const upload = () => {
    if (!product || !parsed) return;
    void start();
  };

  const progressLabel = (() => {
    if (enqueuing) return 'Uploading…';
    if (status === 'QUEUED') return 'Queued…';
    if (itemsProcessed > 0) return `Processing… (${formatInteger(itemsProcessed)} components)`;
    return 'Processing…';
  })();

  return (
    <Dialog open={product != null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload SBOM</DialogTitle>
          <DialogDescription>
            {product ? (
              <>
                Attach a CycloneDX or SPDX SBOM to{' '}
                <span className="font-medium">{product.name}</span>. It becomes the active SBOM and
                is scanned in the background.
              </>
            ) : null}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="product-version">Product version</Label>
            <Input
              id="product-version"
              placeholder="e.g. v2.4.0 or 2026.Q1.1 (optional)"
              value={productVersion}
              onChange={(event) => setProductVersion(event.target.value)}
              disabled={running}
            />
            <p className="text-xs text-muted-foreground">
              Labels this scan in the version history. Defaults to “Unknown”.
            </p>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="sbom-file">SBOM file (JSON)</Label>
            <label
              htmlFor="sbom-file"
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
                  <span>Click to select a CycloneDX or SPDX SBOM</span>
                </>
              )}
            </label>
            <Input
              ref={inputRef}
              id="sbom-file"
              type="file"
              accept=".json,application/json"
              className="sr-only"
              disabled={running}
              onChange={(event) => void handleFile(event.target.files?.[0])}
            />
            {fileError && <p className="text-sm font-medium text-destructive">{fileError}</p>}
          </div>

          {status && (
            <div className="flex items-center gap-2 rounded-md border border-border bg-muted/50 p-3 text-sm">
              <JobStatusBadge status={status} />
              <span className="text-muted-foreground">
                {status === 'FAILED' || status === 'CANCELLED'
                  ? (message ??
                    'The upload did not finish. You can retry without re-selecting the file.')
                  : (message ?? progressLabel)}
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
          <Button type="button" onClick={upload} disabled={!parsed || running}>
            {running && <Loader2 className="h-4 w-4 animate-spin" />}
            {running ? progressLabel : 'Start Analysis'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
