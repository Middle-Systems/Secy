import { useState } from 'react';
import { Check, Clock, Copy, History, Loader2, Trash2, Upload } from 'lucide-react';
import { toast } from 'sonner';

import { useDeleteProduct } from '@/api/queries';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter } from '@/components/ui/card';
import { formatDate, formatDateTime, formatInteger } from '@/lib/format';
import { cn } from '@/lib/utils';

import type { DerivedProduct, SbomStatusDisplay } from './product.types';

const STATUS_STYLES: Record<SbomStatusDisplay, string> = {
  Scanning: 'bg-severity-medium/10 text-severity-medium',
  Complete: 'bg-severity-low/10 text-severity-low',
  Failed: 'bg-destructive/10 text-destructive',
  Unknown: 'bg-muted text-muted-foreground',
};

interface ProductCardProps {
  product: DerivedProduct;
  onUploadSbom: (product: DerivedProduct) => void;
  onViewVulnerabilities: (product: DerivedProduct) => void;
  onViewHistory: (product: DerivedProduct) => void;
}

/**
 * One product tile: identity + SBOM-derived posture (active-SBOM status,
 * total findings, actionable pill) and the four card actions. Ports the Angular
 * `product-catalog` card.
 */
export function ProductCard({
  product,
  onUploadSbom,
  onViewVulnerabilities,
  onViewHistory,
}: ProductCardProps) {
  const [copied, setCopied] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const deleteProduct = useDeleteProduct();

  const status = product.activeSbomStatusDisplay;
  const hasActiveSbom = Boolean(product.activeSbomId);
  const shortId = product.id.slice(0, 8);

  const copyId = async () => {
    try {
      await navigator.clipboard?.writeText(product.id);
      setCopied(true);
      toast.success('Product ID copied to clipboard');
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Could not copy the Product ID');
    }
  };

  const handleDelete = async () => {
    try {
      await deleteProduct.mutateAsync(product.id);
      toast.success(`Deleted "${product.name}"`);
      setConfirmOpen(false);
    } catch {
      toast.error(`Could not delete "${product.name}"`);
    }
  };

  return (
    <Card className="flex h-full flex-col">
      <CardContent className="flex flex-1 flex-col gap-3 p-5">
        <div className="flex items-start justify-between gap-2">
          <h3 className="min-w-0 truncate text-base font-bold text-foreground" title={product.name}>
            {product.name}
          </h3>
          <span
            className={cn(
              'shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
              STATUS_STYLES[status],
            )}
          >
            {status}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          <button
            type="button"
            onClick={copyId}
            title="Copy full Product ID"
            className="inline-flex items-center gap-1 rounded font-mono hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {copied ? (
              <Check className="h-3 w-3 text-severity-low" aria-hidden="true" />
            ) : (
              <Copy className="h-3 w-3" aria-hidden="true" />
            )}
            {shortId}…
          </button>
          <span aria-hidden="true">·</span>
          <span className="inline-flex items-center gap-1" title="Created">
            <Clock className="h-3 w-3" aria-hidden="true" />
            {formatDate(product.createdAt)}
          </span>
          {product.lastScanned && (
            <>
              <span aria-hidden="true">·</span>
              <span title="Last scanned">Scanned {formatDateTime(product.lastScanned)}</span>
            </>
          )}
        </div>

        <div className="flex items-stretch gap-3 rounded-lg border border-border p-3">
          <div className="flex-1">
            <div className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
              Total Findings
            </div>
            <div className="text-xl font-bold text-foreground">
              {formatInteger(product.vulnerabilityCount)}
            </div>
          </div>
          <div className="w-px bg-border" aria-hidden="true" />
          <div className="flex-1">
            <div className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
              Actionable
            </div>
            <div
              className={cn(
                'inline-flex items-center rounded-full px-2 py-0.5 text-sm font-bold',
                product.actionableCount > 0
                  ? 'bg-destructive/10 text-destructive'
                  : 'bg-muted text-muted-foreground',
              )}
            >
              {formatInteger(product.actionableCount)}
            </div>
          </div>
        </div>

        {product.description && (
          <p className="line-clamp-3 text-sm text-muted-foreground">{product.description}</p>
        )}
      </CardContent>

      <CardFooter className="flex flex-wrap items-center gap-2 border-t border-border p-3">
        <Button variant="secondary" size="sm" onClick={() => onUploadSbom(product)}>
          <Upload className="h-4 w-4" />
          Upload SBOM
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!hasActiveSbom}
          title={hasActiveSbom ? undefined : 'No active SBOM to inspect yet'}
          onClick={() => onViewVulnerabilities(product)}
        >
          View Vulnerabilities
        </Button>
        <Button variant="ghost" size="sm" onClick={() => onViewHistory(product)}>
          <History className="h-4 w-4" />
          History
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="ml-auto text-muted-foreground hover:text-destructive"
          aria-label={`Delete ${product.name}`}
          title="Delete product"
          onClick={() => setConfirmOpen(true)}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </CardFooter>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{product.name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes the product and every SBOM and finding attached to it. This
              cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteProduct.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleDelete();
              }}
              disabled={deleteProduct.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteProduct.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
