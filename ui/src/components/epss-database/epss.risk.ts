/**
 * EPSS risk bucketing.
 *
 * The FIRST EPSS score is a 0–1 probability that a CVE will be exploited in the
 * wild within 30 days. These thresholds mirror the Angular `epss-database` view:
 *
 * | score      | level      | label                 |
 * |------------|------------|-----------------------|
 * | `> 0.10`   | `critical` | "Critical Probability"|
 * | `> 0.05`   | `high`     | "High Probability"    |
 * | `> 0.01`   | `elevated` | "Elevated"            |
 * | otherwise  | `low`      | "Low Risk"            |
 *
 * Comparisons are strictly `>`, so the exact boundary values (0.1, 0.05, 0.01)
 * fall into the lower bucket.
 */

export type EpssRiskLevel = 'critical' | 'high' | 'elevated' | 'low';

export interface EpssRisk {
  /** Machine-readable bucket. */
  level: EpssRiskLevel;
  /** Human label for the risk pill. */
  label: string;
  /** Tailwind classes for a tinted pill — `bg-…/10 text-…` on the severity ramp. */
  colorClass: string;
  /**
   * Tailwind class that colours the shadcn `<Progress>` indicator. It targets
   * the indicator via a child selector so it can be dropped straight onto the
   * `<Progress className>` — `[&>div]:bg-severity-…`.
   */
  barClass: string;
}

const CRITICAL: EpssRisk = {
  level: 'critical',
  label: 'Critical Probability',
  colorClass: 'bg-severity-critical/10 text-severity-critical',
  barClass: '[&>div]:bg-severity-critical',
};

const HIGH: EpssRisk = {
  level: 'high',
  label: 'High Probability',
  colorClass: 'bg-severity-high/10 text-severity-high',
  barClass: '[&>div]:bg-severity-high',
};

const ELEVATED: EpssRisk = {
  level: 'elevated',
  label: 'Elevated',
  colorClass: 'bg-severity-medium/10 text-severity-medium',
  barClass: '[&>div]:bg-severity-medium',
};

const LOW: EpssRisk = {
  level: 'low',
  label: 'Low Risk',
  colorClass: 'bg-severity-low/10 text-severity-low',
  barClass: '[&>div]:bg-severity-low',
};

/** Classify an EPSS score (0–1). Non-finite input is treated as `low`. */
export function epssRisk(score: number): EpssRisk {
  if (!Number.isFinite(score)) return LOW;
  if (score > 0.1) return CRITICAL;
  if (score > 0.05) return HIGH;
  if (score > 0.01) return ELEVATED;
  return LOW;
}
