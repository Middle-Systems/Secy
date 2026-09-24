/**
 * Pure helpers + persisted preferences for the Actionable Items view.
 *
 * The two opt-in toggles ("only with a fix" / "only with a known exploit") are
 * remembered per-user in `localStorage`, per the roadmap. Every read and write
 * is wrapped in try/catch and defaults to show-all — a private window, cleared
 * storage or a thrown accessor must never break the screen.
 */
import type { ActionableItem, TriageSnapshot, TriageState, User } from '@/api/types';
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

/* -------------------------------------------------------------------------- */
/* Triage (Phase 7)                                                          */
/* -------------------------------------------------------------------------- */

export const TRIAGE_STATE_LABELS: Record<TriageState, string> = {
  OPEN: 'Open',
  ACKNOWLEDGED: 'Acknowledged',
  SNOOZED: 'Snoozed',
  RESOLVED: 'Resolved',
  FALSE_POSITIVE: 'False positive',
};

/** Every triage state, declaration order — the order every state `<Select>` in this feature lists them in. */
export const TRIAGE_STATES: TriageState[] = [
  'OPEN',
  'ACKNOWLEDGED',
  'SNOOZED',
  'RESOLVED',
  'FALSE_POSITIVE',
];

/** Pluck the triage fields off a row to seed `ActionableDetailPanel`'s controls — see {@link TriageSnapshot}. */
export function triageSnapshotOf(item: ActionableItem): TriageSnapshot {
  return {
    triageState: item.triageState,
    assigneeId: item.assigneeId,
    assigneeName: item.assigneeName,
    snoozedUntil: item.snoozedUntil,
  };
}

/** `displayName` falls back to `email` per the assignee-picker contract (`GET /api/users`). */
export function userLabel(user: Pick<User, 'email' | 'displayName'>): string {
  return user.displayName?.trim() || user.email;
}

/**
 * Convert a `datetime-local` input's value ("2026-09-24T14:30", wall-clock,
 * no offset) to the wire format `snoozedUntil` expects. The backend's
 * `snoozedUntil` is a plain Java `LocalDateTime` — the same no-timezone shape
 * every other date field on `ActionableItem` uses (e.g. `createdAt`,
 * "2026-09-05T14:22:31.118") — so this is passed through with seconds
 * appended, **not** round-tripped through `Date`/`toISOString()`: that would
 * convert to UTC and append `Z`, which silently shifts the time by the
 * browser's offset and fails Jackson's zone-less `LocalDateTime` parser.
 * Empty input yields `null`.
 */
export function datetimeLocalToIso(value: string): string | null {
  if (!value) return null;
  // A `datetime-local` value is always "YYYY-MM-DDTHH:mm" or
  // "YYYY-MM-DDTHH:mm:ss" when non-empty — the browser guarantees the shape.
  return value.length === 16 ? `${value}:00` : value;
}

/**
 * Convert an ISO-8601 string from the wire to the local-time value a
 * `datetime-local` input expects ("2026-09-24T14:30"). Nullish/unparseable
 * input yields "".
 */
export function isoToDatetimeLocal(iso: string | null | undefined): string {
  if (!iso) return '';
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}T${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`;
}
