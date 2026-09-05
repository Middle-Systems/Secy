/** Sentinel emitted by {@link getVisiblePages} where page numbers are skipped. */
export const ELLIPSIS = 'ellipsis' as const;

export type PageToken = number | typeof ELLIPSIS;

/**
 * Windowed list of page indexes to render, with ellipsis gaps — ported from the
 * Angular CVE view's `getVisiblePages()`.
 *
 * All indexes are **0-based** (Spring `Page.number`). Up to `2 * windowSize + 1`
 * pages are shown around `current`, always flanked by the first and last page.
 * Below `2 * windowSize + 3` total pages every page is listed (no ellipsis).
 *
 * @example getVisiblePages(20, 9)  // [0, 'ellipsis', 7, 8, 9, 10, 11, 'ellipsis', 19]
 * @example getVisiblePages(4, 0)   // [0, 1, 2, 3]
 */
export function getVisiblePages(
  totalPages: number,
  current: number,
  windowSize = 2,
): PageToken[] {
  const total = Math.max(0, Math.floor(totalPages));
  if (total === 0) return [];

  const threshold = 2 * windowSize + 3;
  if (total <= threshold) {
    return Array.from({ length: total }, (_, i) => i);
  }

  const clamped = Math.min(Math.max(current, 0), total - 1);
  const pages: PageToken[] = [0];

  if (clamped > windowSize + 1) pages.push(ELLIPSIS);

  const start = Math.max(1, clamped - windowSize);
  const end = Math.min(total - 2, clamped + windowSize);
  for (let i = start; i <= end; i++) pages.push(i);

  if (clamped < total - windowSize - 2) pages.push(ELLIPSIS);

  pages.push(total - 1);
  return pages;
}

/** 1-based "Showing X–Y of Z" range for the current page. */
export function pageRange(
  page: number,
  size: number,
  totalElements: number,
): { from: number; to: number } {
  if (totalElements <= 0 || size <= 0) return { from: 0, to: 0 };
  const from = page * size + 1;
  const to = Math.min((page + 1) * size, totalElements);
  return { from: Math.min(from, totalElements), to };
}
