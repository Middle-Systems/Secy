/**
 * Pure derivations for the Dashboard view.
 *
 * Everything the dashboard shows beyond the KPI numbers and the global severity
 * counts is computed client-side from the KEV catalog (`GET /api/kev`) — there
 * is no dedicated endpoint. Keep that logic here (tested) rather than inline in
 * the view.
 */
import type { KEV } from '@/api/types';

export interface VendorCount {
  vendor: string;
  count: number;
}

/** Count occurrences of each key across `items`; blank/nullish keys are skipped. */
export function countBy<T>(
  items: readonly T[],
  key: (item: T) => string | null | undefined,
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return counts;
}

/** The `n` highest counts, descending; ties broken alphabetically for stability. */
export function topN(counts: Map<string, number>, n: number): VendorCount[] {
  return [...counts.entries()]
    .map(([vendor, count]) => ({ vendor, count }))
    .sort((a, b) => b.count - a.count || a.vendor.localeCompare(b.vendor))
    .slice(0, Math.max(0, n));
}

/** Top `n` vendors by number of KEV entries across the whole catalog. */
export function topVendorsByExposure(kev: readonly KEV[], n = 8): VendorCount[] {
  return topN(
    countBy(kev, (k) => k.vendor?.trim()),
    n,
  );
}

/** Whether a KEV entry is linked to a known ransomware campaign. */
export function isKnownRansomware(kev: Pick<KEV, 'knownRansomwareCampaignUse'>): boolean {
  return kev.knownRansomwareCampaignUse === 'Known';
}

/** Top `n` vendors by number of ransomware-linked KEV entries. */
export function topRansomwareTargets(kev: readonly KEV[], n = 5): VendorCount[] {
  return topN(
    countBy(kev.filter(isKnownRansomware), (k) => k.vendor?.trim()),
    n,
  );
}

/** The `n` most recently `added` KEV entries, newest first. */
export function recentlyAddedKev(kev: readonly KEV[], n = 10): KEV[] {
  const withTime = kev.map((k) => ({ k, t: new Date(k.added).getTime() }));
  withTime.sort((a, b) => {
    const at = Number.isNaN(a.t) ? -Infinity : a.t;
    const bt = Number.isNaN(b.t) ? -Infinity : b.t;
    return bt - at;
  });
  return withTime.slice(0, Math.max(0, n)).map((x) => x.k);
}
