import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  daysFromNow,
  formatDate,
  formatDateTime,
  formatInteger,
  formatLongDate,
  formatPercent,
  formatRelativeDate,
  isWithinDays,
} from './format';

describe('formatInteger', () => {
  it('adds thousands separators', () => {
    expect(formatInteger(1234567)).toBe('1,234,567');
  });

  it('rounds and guards non-finite input', () => {
    expect(formatInteger(12.6)).toBe('13');
    expect(formatInteger(undefined)).toBe('0');
    expect(formatInteger(null)).toBe('0');
    expect(formatInteger(Number.NaN)).toBe('0');
    expect(formatInteger(Infinity)).toBe('0');
  });
});

describe('formatDate', () => {
  it('formats an ISO string as a medium date', () => {
    expect(formatDate('2026-09-03T19:00:00')).toBe('Sep 3, 2026');
  });

  it('handles empty and unparseable input', () => {
    expect(formatDate('')).toBe('—');
    expect(formatDate(undefined)).toBe('—');
    expect(formatDate(null)).toBe('—');
    expect(formatDate('not-a-date')).toBe('not-a-date');
  });
});

describe('formatLongDate', () => {
  it('formats an ISO string as a long date', () => {
    expect(formatLongDate('2026-09-03T19:00:00')).toBe('September 3, 2026');
  });

  it('falls back like formatDate', () => {
    expect(formatLongDate('')).toBe('—');
    expect(formatLongDate('nope')).toBe('nope');
  });
});

describe('formatDateTime', () => {
  it('includes the time', () => {
    expect(formatDateTime('2026-09-03T19:00:00')).toBe('Sep 3, 2026, 7:00 PM');
  });

  it('falls back like formatDate', () => {
    expect(formatDateTime(undefined)).toBe('—');
  });
});

describe('formatPercent', () => {
  it('turns a 0–1 float into a percent string', () => {
    expect(formatPercent(0.123)).toBe('12.3%');
    expect(formatPercent(1)).toBe('100.0%');
    expect(formatPercent(0)).toBe('0.0%');
  });

  it('respects the digits argument', () => {
    expect(formatPercent(0.98765, 2)).toBe('98.77%');
    expect(formatPercent(0.5, 0)).toBe('50%');
  });

  it('guards nullish / non-finite input', () => {
    expect(formatPercent(null)).toBe('—');
    expect(formatPercent(undefined)).toBe('—');
    expect(formatPercent(Number.NaN)).toBe('—');
  });
});

describe('relative-date helpers', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-05T12:00:00Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('daysFromNow is signed and NaN-safe', () => {
    expect(daysFromNow('2026-09-05T12:00:00Z')).toBe(0);
    expect(daysFromNow('2026-09-08T12:00:00Z')).toBe(3);
    expect(daysFromNow('2026-09-02T12:00:00Z')).toBe(-3);
    expect(daysFromNow('bad')).toBeNaN();
    expect(daysFromNow(undefined)).toBeNaN();
  });

  it('isWithinDays only counts recent past dates', () => {
    expect(isWithinDays('2026-09-01T12:00:00Z', 7)).toBe(true);
    expect(isWithinDays('2026-08-01T12:00:00Z', 7)).toBe(false);
    expect(isWithinDays('2026-09-20T12:00:00Z', 7)).toBe(false);
    expect(isWithinDays('bad', 7)).toBe(false);
  });

  it('formatRelativeDate produces friendly strings near now', () => {
    expect(formatRelativeDate('2026-09-05T12:00:00Z')).toBe('today');
    expect(formatRelativeDate('2026-09-04T12:00:00Z')).toBe('yesterday');
    expect(formatRelativeDate('2026-09-08T12:00:00Z')).toBe('in 3 days');
  });

  it('formatRelativeDate falls back to an absolute date when far away', () => {
    expect(formatRelativeDate('2027-01-01T12:00:00Z')).toBe('Jan 1, 2027');
    expect(formatRelativeDate('')).toBe('—');
  });
});
