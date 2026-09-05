import {
  resolveSeverityLevel,
  severityLevelFromString,
  SEVERITY_LABELS,
  type SeverityLevel,
} from '@/lib/severity';
import { cn } from '@/lib/utils';

const LEVEL_STYLES: Record<SeverityLevel, string> = {
  critical: 'bg-severity-critical/10 text-severity-critical',
  high: 'bg-severity-high/10 text-severity-high',
  medium: 'bg-severity-medium/10 text-severity-medium',
  low: 'bg-severity-low/10 text-severity-low',
  unknown: 'bg-muted text-muted-foreground',
};

interface SeverityBadgeProps {
  /**
   * A severity label — `BaseSeverity` ("CRITICAL" …) or any string. When it is
   * not a recognised bucket, `score` is used to pick the colour.
   */
  severity?: string | null;
  /**
   * Optional CVSS score (0–10). Drives the bucket when `severity` is
   * missing/unknown.
   */
  score?: number | null;
  /** Override the visible text (defaults to the bucket name, or the raw `severity`). */
  label?: string;
  className?: string;
}

/**
 * Small severity pill using the `severity-{critical,high,medium,low}` tokens on a
 * tinted background. Unknown / null / "NONE" render a neutral "Unknown".
 *
 * @example <SeverityBadge severity={cve.baseSeverity} score={cve.cvssScore} />
 * @example <SeverityBadge score={7.5} />            // → "High"
 * @example <SeverityBadge severity="CRITICAL" />    // → "Critical"
 */
export function SeverityBadge({ severity, score, label, className }: SeverityBadgeProps) {
  const level = resolveSeverityLevel(severity, score);
  const knownLabel = severityLevelFromString(severity) !== 'unknown';
  const text = label ?? (knownLabel || !severity ? SEVERITY_LABELS[level] : severity);

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold',
        LEVEL_STYLES[level],
        className,
      )}
    >
      {text}
    </span>
  );
}
