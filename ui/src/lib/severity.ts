/**
 * Severity bucketing shared by the CVE / KEV / EPSS / product-catalog views.
 * Pure — the visual pill lives in `components/common/SeverityBadge.tsx`.
 */

/** The severity buckets Secy renders. `unknown` is the catch-all. */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
};

/** Normalise a `baseSeverity` string ("CRITICAL", "High", "none", …) to a bucket. */
export function severityLevelFromString(
  severity: string | null | undefined,
): SeverityLevel {
  switch (severity?.trim().toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'unknown';
  }
}

/**
 * Map a CVSS base score (0–10) to a bucket, matching the NVD qualitative ramp
 * used by the Angular CVE view: ≥9 critical, ≥7 high, ≥4 medium, >0 low.
 */
export function severityLevelFromScore(score: number | null | undefined): SeverityLevel {
  if (score == null || !Number.isFinite(score) || score <= 0) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Resolve the bucket from a label first, then a score. `severity` wins when it
 * is a recognised bucket; otherwise `score` is consulted.
 */
export function resolveSeverityLevel(
  severity: string | null | undefined,
  score: number | null | undefined,
): SeverityLevel {
  const fromString = severityLevelFromString(severity);
  return fromString !== 'unknown' ? fromString : severityLevelFromScore(score);
}
