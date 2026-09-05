import { Loader2 } from 'lucide-react';

/**
 * Fallback shown while a lazily-loaded route view chunk is in flight
 * (see `router.ts` → `defaultPendingComponent`). Mirrors the centered
 * spinner the individual views use for their own data loads.
 */
export function RoutePending() {
  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center text-center">
      <Loader2 className="h-12 w-12 animate-spin text-primary" aria-hidden="true" />
      <p className="sr-only">Loading…</p>
    </div>
  );
}
