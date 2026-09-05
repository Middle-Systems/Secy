import { describe, expect, it } from 'vitest';

import { ELLIPSIS, getVisiblePages, pageRange } from './pagination.helpers';

describe('getVisiblePages', () => {
  it('returns nothing for zero pages', () => {
    expect(getVisiblePages(0, 0)).toEqual([]);
  });

  it('lists every page when at or below the ellipsis threshold', () => {
    expect(getVisiblePages(1, 0)).toEqual([0]);
    expect(getVisiblePages(4, 2)).toEqual([0, 1, 2, 3]);
    expect(getVisiblePages(7, 3)).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  it('windows around the current page with both ellipses', () => {
    expect(getVisiblePages(20, 9)).toEqual([0, ELLIPSIS, 7, 8, 9, 10, 11, ELLIPSIS, 19]);
  });

  it('drops the leading ellipsis near the start', () => {
    expect(getVisiblePages(20, 1)).toEqual([0, 1, 2, 3, ELLIPSIS, 19]);
  });

  it('drops the trailing ellipsis near the end', () => {
    expect(getVisiblePages(20, 18)).toEqual([0, ELLIPSIS, 16, 17, 18, 19]);
  });

  it('clamps an out-of-range current page', () => {
    expect(getVisiblePages(20, 99)).toEqual([0, ELLIPSIS, 17, 18, 19]);
    expect(getVisiblePages(20, -5)).toEqual([0, 1, 2, ELLIPSIS, 19]);
  });

  it('honours a custom window size', () => {
    expect(getVisiblePages(20, 10, 1)).toEqual([0, ELLIPSIS, 9, 10, 11, ELLIPSIS, 19]);
  });
});

describe('pageRange', () => {
  it('computes the 1-based showing X–Y range', () => {
    expect(pageRange(0, 15, 100)).toEqual({ from: 1, to: 15 });
    expect(pageRange(2, 15, 100)).toEqual({ from: 31, to: 45 });
    expect(pageRange(6, 15, 100)).toEqual({ from: 91, to: 100 });
  });

  it('is zero when there is nothing to show', () => {
    expect(pageRange(0, 15, 0)).toEqual({ from: 0, to: 0 });
  });
});
