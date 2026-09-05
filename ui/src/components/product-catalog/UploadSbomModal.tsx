import { useRef, useState } from 'react';
import { FileJson, Loader2, UploadCloud } from 'lucide-react';
import { toast } from 'sonner';

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
import { Label } from '@/components/ui/label';

import type { DerivedProduct } from './product.types';

interface UploadSbomModalProps {
  product: DerivedProduct | null;
  onOpenChange: (open: boolean) => void;
}

interface ParsedFile {
  name: string;
  sbom: unknown;
}

/** Loose CycloneDX shape check — enough to reject an obviously wrong file. */
function looksLikeCycloneDx(doc: unknown): boolean {
  if (doc == null || typeof doc !== 'object') return false;
  const record = doc as Record<string, unknown>;
  const bomFormat = typeof record.bomFormat === 'string' ? record.bomFormat.toLowerCase() : '';
  return bomFormat === 'cyclonedx' || Array.isArray(record.components);
}

/**
 * "Upload SBOM" dialog — reads a `.json` file locally, parses it, sanity-checks
 * that it is CycloneDX, then posts through `useUploadSbom`. Ports the Angular
 * `UploadSbomModalComponent` (file read + `JSON.parse` + POST).
 */
export function UploadSbomModal({ product, onOpenChange }: UploadSbomModalProps) {
  const uploadSbom = useUploadSbom();
  const inputRef = useRef<HTMLInputElement>(null);
  const [productVersion, setProductVersion] = useState('');
  const [parsed, setParsed] = useState<ParsedFile | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

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
    if (!looksLikeCycloneDx(doc)) {
      setFileError(
        'This does not look like a CycloneDX SBOM (expected `bomFormat: "CycloneDX"` or a `components` array).',
      );
      return;
    }
    setParsed({ name: file.name, sbom: doc });
  };

  const upload = async () => {
    if (!product || !parsed) return;
    try {
      await uploadSbom.mutateAsync({
        productId: product.id,
        sbom: parsed.sbom,
        productVersion: productVersion.trim() || undefined,
      });
      toast.success('SBOM uploaded — scanning has started.');
      handleOpenChange(false);
    } catch {
      toast.error('Upload failed. Check the file and the backend, then try again.');
    }
  };

  return (
    <Dialog open={product != null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload SBOM</DialogTitle>
          <DialogDescription>
            {product ? (
              <>
                Attach a CycloneDX SBOM to <span className="font-medium">{product.name}</span>. It
                becomes the active SBOM and is scanned immediately.
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
                  <span>Click to select a CycloneDX SBOM</span>
                </>
              )}
            </label>
            <Input
              ref={inputRef}
              id="sbom-file"
              type="file"
              accept=".json,application/json"
              className="sr-only"
              onChange={(event) => void handleFile(event.target.files?.[0])}
            />
            {fileError && <p className="text-sm font-medium text-destructive">{fileError}</p>}
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => handleOpenChange(false)}
            disabled={uploadSbom.isPending}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void upload()}
            disabled={!parsed || uploadSbom.isPending}
          >
            {uploadSbom.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Start Analysis
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
