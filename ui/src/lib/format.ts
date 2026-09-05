/**
 * Display formatters shared by every Secy view.
 *
 * All of these are presentational and defensive: nullish / empty / unparseable
 * input never throws, it degrades to a readable placeholder. The date helpers
 * take the ISO-8601 **strings** the backend actually sends (see the note in
 * `src/api/types.ts`) — never `Date` objects.
 */

const integerFormatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/** Em dash used wherever a value is missing. */
export const EM_DASH = '—';

/** Format an integer with thousands separators. Non-finite input becomes "0". */
export function formatInteger(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return '0';
  return integerFormatter.format(Math.round(value));
}

const dateFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
});

const dateTimeFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
});

const longDateFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
});

/**
 * Format an ISO-8601 string as a medium date — "Sep 3, 2026". Empty/nullish
 * input renders an em dash; an unparseable string is returned unchanged.
 */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return EM_DASH;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return dateFormatter.format(parsed);
}

/**
 * Format an ISO-8601 string as a full date — "September 3, 2026". Used for the
 * prominent "federal action deadline" style dates. Same fallbacks as
 * {@link formatDate}.
 */
export function formatLongDate(iso: string | null | undefined): string {
  if (!iso) return EM_DASH;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return longDateFormatter.format(parsed);
}

/**
 * Format an ISO-8601 string as date + time — "Sep 3, 2026, 7:00 PM". Same
 * fallbacks as {@link formatDate}.
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return EM_DASH;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return dateTimeFormatter.format(parsed);
}

/**
 * Format a 0–1 probability as a percent string — `formatPercent(0.123)` → "12.3%".
 * `digits` controls fraction digits (default 1). Nullish / non-finite → em dash.
 */
export function formatPercent(
  fraction: number | null | undefined,
  digits = 1,
): string {
  if (fraction == null || !Number.isFinite(fraction)) return EM_DASH;
  return new Intl.NumberFormat('en-US', {
    style: 'percent',
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(fraction);
}

const MS_PER_DAY = 1000 * 60 * 60 * 24;

/** Whole days between `iso` and now — negative for past dates. NaN when unparseable. */
export function daysFromNow(iso: string | null | undefined): number {
  if (!iso) return Number.NaN;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return Number.NaN;
  return Math.round((parsed.getTime() - Date.now()) / MS_PER_DAY);
}

/** True when `iso` is a valid date within the last `days` days (not in the future). */
export function isWithinDays(iso: string | null | undefined, days: number): boolean {
  const delta = daysFromNow(iso);
  if (Number.isNaN(delta)) return false;
  return delta <= 0 && delta >= -days;
}

const relativeFormatter = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' });

/**
 * Human relative date — "today", "yesterday", "3 days ago", "in 2 days".
 * Anything more than ~30 days away falls back to {@link formatDate}. Same
 * nullish / unparseable fallbacks as {@link formatDate}.
 */
export function formatRelativeDate(iso: string | null | undefined): string {
  if (!iso) return EM_DASH;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  const days = Math.round((parsed.getTime() - Date.now()) / MS_PER_DAY);
  if (Math.abs(days) > 30) return dateFormatter.format(parsed);
  return relativeFormatter.format(days, 'day');
}
