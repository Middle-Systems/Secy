import { useRef, useState } from 'react';
import { FileJson, Loader2, UploadCloud } from 'lucide-react';

import { useProducts, useScanAssetGrype, useScanAssetTrivy } from '@/api/queries';
import type { AssetScanner, AssetType } from '@/api/types';
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
import { formatInteger } from '@/lib/format';

interface ScanAssetModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface ParsedFile {
  name: string;
  report: unknown;
}

const ASSET_TYPE_OPTIONS: { value: AssetType; label: string }[] = [
  { value: 'CONTAINER_IMAGE', label: 'Container image' },
  { value: 'HOST', label: 'Host' },
  { value: 'SERVICE', label: 'Service' },
];

/**
 * Best-effort scanner sniff, same spirit as `UploadSbomModal`'s CycloneDX/SPDX
 * check — a UX nicety, not a substitute for the backend's own validation
 * (`AssetScanParser` is the source of truth and will 400 a mismatched body).
 * Trivy vulnerability reports carry a `Results` array plus `ArtifactName` or
 * `SchemaVersion`; Grype reports carry a `matches` array.
 */
function sniffScanner(doc: unknown): AssetScanner | null {
  if (doc == null || typeof doc !== 'object') return null;
  const record = doc as Record<string, unknown>;
  if (Array.isArray(record.matches)) return 'Grype';
  if (
    Array.isArray(record.Results) &&
    (typeof record.ArtifactName === 'string' || 'SchemaVersion' in record)
  ) {
    return 'Trivy';
  }
  return null;
}

/**
 * "Scan asset" dialog — reads a `.json` scanner report locally, auto-detects
 * Trivy vs. Grype (with a manual override, since the two backend endpoints
 * differ), then posts through {@link useScanAssetTrivy} / {@link useScanAssetGrype}.
 *
 * Mirrors `UploadSbomModal`'s mechanics closely: the POST answers with a `Job`
 * to poll, so this drives the same `useIngestJob` enqueue → poll → settle
 * lifecycle — progress badge while running, success toast + close, and on
 * failure the dialog stays open with the file still selected so the user can
 * retry without re-picking it.
 */
export function ScanAssetModal({ open, onOpenChange }: ScanAssetModalProps) {
  const scanTrivy = useScanAssetTrivy();
  const scanGrype = useScanAssetGrype();
  const products = useProducts();
  const inputRef = useRef<HTMLInputElement>(null);

  const [parsed, setParsed] = useState<ParsedFile | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [scanner, setScanner] = useState<AssetScanner>('Trivy');
  const [autoDetected, setAutoDetected] = useState(false);
  const [name, setName] = useState('');
  const [type, setType] = useState<AssetType>('CONTAINER_IMAGE');
  const [productId, setProductId] = useState<string>('NONE');

  const { start, running, enqueuing, status, itemsProcessed, message } = useIngestJob({
    ingest: () => {
      const mutate = scanner === 'Trivy' ? scanTrivy.mutateAsync : scanGrype.mutateAsync;
      return mutate({
        report: parsed!.report,
        name: name.trim() || undefined,
        type,
        productId: productId === 'NONE' ? undefined : productId,
      });
    },
    startMessage: 'Uploading scan…',
    successMessage: 'Asset scanned and correlated.',
    errorMessage: 'Asset scan failed. Check the file and the backend, then try again.',
    onIngested: () => handleOpenChange(false),
  });

  const reset = () => {
    setParsed(null);
    setFileError(null);
    setScanner('Trivy');
    setAutoDetected(false);
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

    const detected = sniffScanner(doc);
    if (!detected) {
      setFileError(
        'This does not look like a Trivy or Grype JSON report (expected a `Results` array with `ArtifactName`/`SchemaVersion`, or a `matches` array).',
      );
      return;
    }
    setScanner(detected);
    setAutoDetected(true);
    setParsed({ name: file.name, report: doc });
  };

  const upload = () => {
    if (!parsed) return;
    void start();
  };

  const progressLabel = (() => {
    if (enqueuing) return 'Uploading…';
    if (status === 'QUEUED') return 'Queued…';
    if (itemsProcessed > 0) return `Processing… (${formatInteger(itemsProcessed)} components)`;
    return 'Processing…';
  })();

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Scan asset</DialogTitle>
          <DialogDescription>
            Upload a Trivy or Grype JSON report to create or update an asset and correlate its
            findings against the funnel.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="scan-file">Scan report (JSON)</Label>
            <label
              htmlFor="scan-file"
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
                  <span>Click to select a Trivy or Grype JSON report</span>
                </>
              )}
            </label>
            <Input
              ref={inputRef}
              id="scan-file"
              type="file"
              accept=".json,application/json"
              className="sr-only"
              disabled={running}
              onChange={(event) => void handleFile(event.target.files?.[0])}
            />
            {fileError && <p className="text-sm font-medium text-destructive">{fileError}</p>}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-2">
              <Label htmlFor="scanner-select">Scanner</Label>
              <Select
                value={scanner}
                onValueChange={(v) => {
                  setScanner(v as AssetScanner);
                  setAutoDetected(false);
                }}
              >
                <SelectTrigger id="scanner-select" disabled={running}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Trivy">Trivy</SelectItem>
                  <SelectItem value="Grype">Grype</SelectItem>
                </SelectContent>
              </Select>
              {autoDetected && (
                <p className="text-xs text-muted-foreground">Auto-detected from the file.</p>
              )}
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="asset-type-select">Asset type</Label>
              <Select value={type} onValueChange={(v) => setType(v as AssetType)}>
                <SelectTrigger id="asset-type-select" disabled={running}>
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
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="asset-name">Name (optional)</Label>
            <Input
              id="asset-name"
              placeholder="e.g. acme/api:1.4.2"
              value={name}
              onChange={(event) => setName(event.target.value)}
              disabled={running}
            />
            <p className="text-xs text-muted-foreground">
              Defaults to the report's own artifact name when left blank.
            </p>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="asset-product-select">Linked product (optional)</Label>
            <Select value={productId} onValueChange={setProductId}>
              <SelectTrigger id="asset-product-select" disabled={running}>
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
                    'The scan did not finish. You can retry without re-selecting the file.')
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
            {running ? progressLabel : 'Start Scan'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
