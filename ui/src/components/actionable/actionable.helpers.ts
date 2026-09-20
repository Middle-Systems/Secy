/**
 * Pure helpers + persisted preferences for the Actionable Items view.
 *
 * The two opt-in toggles ("only with a fix" / "only with a known exploit") are
 * remembered per-user in `localStorage`, per the roadmap. Every read and write
 * is wrapped in try/catch and defaults to show-all — a private window, cleared
 * storage or a thrown accessor must never break the screen.
 */
import { daysFromNow } from '@/lib/format';

export interface ActionableTogglePrefs {
  /** Maps to `fixState=FIXED`. */
  onlyWithFix: boolean;
  /** Maps to `minExploitMaturity=POC`. */
  onlyWithExploit: boolean;
}

export const DEFAULT_TOGGLE_PREFS: ActionableTogglePrefs = {
  onlyWithFix: false,
  onlyWithExploit: false,
};

const PREFS_KEY = 'secy.actionable.filters';

/** Read the persisted toggle prefs, falling back to show-all on any problem. */
export function readTogglePrefs(): ActionableTogglePrefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return DEFAULT_TOGGLE_PREFS;
    const parsed = JSON.parse(raw) as Partial<ActionableTogglePrefs>;
    return {
      onlyWithFix: Boolean(parsed.onlyWithFix),
      onlyWithExploit: Boolean(parsed.onlyWithExploit),
    };
  } catch {
    return DEFAULT_TOGGLE_PREFS;
  }
}

/** Persist the toggle prefs. Silently no-ops if storage is unavailable. */
export function writeTogglePrefs(prefs: ActionableTogglePrefs): void {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {
    /* storage unavailable — the toggles still work for this session */
  }
}

/** True when a KEV due date is a valid date in the past. */
export function isKevOverdue(dueDate: string | null | undefined): boolean {
  const delta = daysFromNow(dueDate);
  return Number.isFinite(delta) && delta < 0;
}

/** "log4j-core@2.14.1" — component name with an optional `@version` suffix. */
export function componentLabel(
  name: string | null | undefined,
  version: string | null | undefined,
): string {
  if (!name) return version ? `@${version}` : '—';
  return version ? `${name}@${version}` : name;
}

export const REASON_LABELS: Record<string, string> = {
  KEV: 'KEV-listed',
  EPSS_HIGH: 'High EPSS',
  KEV_AND_EPSS_HIGH: 'KEV-listed + high EPSS',
  COMPROMISE: 'Compromise finding',
};

/** `CompromiseType` display labels — the CVE column's replacement on a compromise row. */
export const COMPROMISE_TYPE_LABELS: Record<string, string> = {
  MALICIOUS_PACKAGE: 'Malicious Package',
  MALWARE_HASH: 'Malware Hash',
};

export const EXPLOIT_MATURITY_LABELS: Record<string, string> = {
  NONE: 'None',
  POC: 'PoC',
  WEAPONIZED: 'Weaponized',
  IN_THE_WILD: 'In the wild',
};
