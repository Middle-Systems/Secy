import { useEffect, useMemo, useState } from 'react';
import { Boxes, Plus, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

import { useProducts } from '@/api/queries';
import { ListPageHeader } from '@/components/common/ListPageHeader';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

import { AddProductModal } from './AddProductModal';
import { ProductCard } from './ProductCard';
import { SbomHistoryModal } from './SbomHistoryModal';
import { UploadSbomModal } from './UploadSbomModal';
import { VulnerabilityDetailsModal } from './VulnerabilityDetailsModal';
import { deriveProducts } from './product.derive';
import type { DerivedProduct } from './product.types';

/**
 * Re-fetch cadence. The Angular view polled every 10s so a "Scanning → Complete"
 * transition surfaces without a manual reload. A constant interval is the
 * simplest correct behaviour (the task explicitly allows it).
 */
const POLL_INTERVAL_MS = 10_000;

function CardSkeleton() {
  return (
    <Card className="flex h-full flex-col">
      <CardContent className="flex flex-1 flex-col gap-3 p-5">
        <div className="flex items-center justify-between">
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-5 w-16 rounded-full" />
        </div>
        <Skeleton className="h-3 w-40" />
        <Skeleton className="h-16 w-full rounded-lg" />
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-3 w-2/3" />
      </CardContent>
      <CardFooter className="gap-2 border-t border-border p-3">
        <Skeleton className="h-8 w-28" />
        <Skeleton className="h-8 w-32" />
      </CardFooter>
    </Card>
  );
}

/**
 * Product Catalog — software products and their SBOM-derived vulnerability
 * posture. Roll-up counters are derived client-side (see `product.derive.ts`)
 * because `GET /products` does not serialize them.
 */
export function ProductCatalogView() {
  const query = useProducts({ refetchInterval: POLL_INTERVAL_MS });

  const [addOpen, setAddOpen] = useState(false);
  const [uploadTarget, setUploadTarget] = useState<DerivedProduct | null>(null);
  const [historyTarget, setHistoryTarget] = useState<DerivedProduct | null>(null);
  const [detailsTarget, setDetailsTarget] = useState<DerivedProduct | null>(null);

  useEffect(() => {
    if (query.isError) toast.error('Failed to load the product catalog.');
  }, [query.isError]);

  const products = useMemo(() => deriveProducts(query.data ?? []), [query.data]);

  const showInlineError = query.isError && !query.data;

  return (
    <div className="flex flex-col gap-6">
      <ListPageHeader
        title="Product Catalog"
        subtitle="Your software products and their SBOM-derived vulnerability posture."
        actions={
          <Button onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4" />
            Add Product
          </Button>
        }
      />

      {query.isPending ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <CardSkeleton key={index} />
          ))}
        </div>
      ) : showInlineError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-16 text-center">
          <ShieldAlert className="h-8 w-8 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">Unable to load the product catalog</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            The products service did not respond. Check that the backend is running, then retry.
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={() => void query.refetch()}
          >
            Retry
          </Button>
        </div>
      ) : products.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-border py-16 text-center">
          <Boxes className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">
            No products yet — add one to start tracking its SBOM.
          </p>
          <Button variant="outline" size="sm" className="mt-2" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4" />
            Add Product
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {products.map((product) => (
            <ProductCard
              key={product.id}
              product={product}
              onUploadSbom={setUploadTarget}
              onViewVulnerabilities={setDetailsTarget}
              onViewHistory={setHistoryTarget}
            />
          ))}
        </div>
      )}

      <AddProductModal open={addOpen} onOpenChange={setAddOpen} />

      <UploadSbomModal
        product={uploadTarget}
        onOpenChange={(open) => {
          if (!open) setUploadTarget(null);
        }}
      />

      <SbomHistoryModal
        product={historyTarget}
        onOpenChange={(open) => {
          if (!open) setHistoryTarget(null);
        }}
      />

      <VulnerabilityDetailsModal
        sbomId={detailsTarget?.activeSbomId ?? null}
        productName={detailsTarget?.name}
        onOpenChange={(open) => {
          if (!open) setDetailsTarget(null);
        }}
      />
    </div>
  );
}
