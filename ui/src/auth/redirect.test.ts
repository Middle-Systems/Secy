import { describe, expect, it } from 'vitest';

import { DEFAULT_REDIRECT, safeRedirect } from '@/auth/redirect';

describe('safeRedirect', () => {
  it('keeps a same-origin path', () => {
    expect(safeRedirect('/kev-database')).toBe('/kev-database');
    expect(safeRedirect('/nvd?page=2')).toBe('/nvd?page=2');
  });

  it('falls back when there is nothing to return to', () => {
    expect(safeRedirect(undefined)).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect(null)).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect('')).toBe(DEFAULT_REDIRECT);
  });

  it('refuses anything that could leave the origin', () => {
    // The whole point of the helper: a `redirect` param is attacker-supplied.
    expect(safeRedirect('https://evil.example')).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect('//evil.example')).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect('/\\evil.example')).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect('javascript:alert(1)')).toBe(DEFAULT_REDIRECT);
  });

  it('does not bounce back to the login screen', () => {
    expect(safeRedirect('/login')).toBe(DEFAULT_REDIRECT);
    expect(safeRedirect('/login?redirect=%2Fdashboard')).toBe(DEFAULT_REDIRECT);
  });
});
