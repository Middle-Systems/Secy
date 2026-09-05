import { describe, expect, it } from 'vitest';

import type { KEV } from '@/api/types';

import {
  countBy,
  isKnownRansomware,
  recentlyAddedKev,
  topN,
  topRansomwareTargets,
  topVendorsByExposure,
} from './dashboard.helpers';

function kev(overrides: Partial<KEV>): KEV {
  return {
    cveId: 'CVE-2026-0001',
    vendor: 'Acme',
    product: 'Widget',
    name: 'Some flaw',
    added: '2026-01-01T00:00:00',
    description: '',
    requiredActions: '',
    dueDate: '2026-02-01T00:00:00',
    knownRansomwareCampaignUse: 'Unknown',
    notes: '',
    ...overrides,
  };
}

describe('countBy / topN', () => {
  it('counts keys and skips blank ones', () => {
    const counts = countBy(['a', 'a', 'b', '', undefined as unknown as string], (x) => x);
    expect(counts.get('a')).toBe(2);
    expect(counts.get('b')).toBe(1);
    expect(counts.has('')).toBe(false);
  });

  it('returns the top N, ties broken alphabetically', () => {
    const counts = new Map([
      ['Zeta', 2],
      ['Alpha', 2],
      ['Beta', 5],
    ]);
    expect(topN(counts, 2)).toEqual([
      { vendor: 'Beta', count: 5 },
      { vendor: 'Alpha', count: 2 },
    ]);
  });
});

describe('topVendorsByExposure', () => {
  it('ranks vendors by KEV frequency and trims whitespace', () => {
    const catalog = [
      kev({ vendor: 'Microsoft' }),
      kev({ vendor: 'Microsoft ' }),
      kev({ vendor: 'Cisco' }),
      kev({ vendor: 'Adobe' }),
      kev({ vendor: 'Microsoft' }),
    ];
    const result = topVendorsByExposure(catalog, 2);
    expect(result).toEqual([
      { vendor: 'Microsoft', count: 3 },
      { vendor: 'Adobe', count: 1 },
    ]);
  });
});

describe('isKnownRansomware / topRansomwareTargets', () => {
  it('detects known ransomware use', () => {
    expect(isKnownRansomware(kev({ knownRansomwareCampaignUse: 'Known' }))).toBe(true);
    expect(isKnownRansomware(kev({ knownRansomwareCampaignUse: 'Unknown' }))).toBe(false);
  });

  it('ranks only ransomware-linked entries by vendor', () => {
    const catalog = [
      kev({ vendor: 'Fortinet', knownRansomwareCampaignUse: 'Known' }),
      kev({ vendor: 'Fortinet', knownRansomwareCampaignUse: 'Known' }),
      kev({ vendor: 'Fortinet', knownRansomwareCampaignUse: 'Unknown' }),
      kev({ vendor: 'Ivanti', knownRansomwareCampaignUse: 'Known' }),
    ];
    expect(topRansomwareTargets(catalog, 5)).toEqual([
      { vendor: 'Fortinet', count: 2 },
      { vendor: 'Ivanti', count: 1 },
    ]);
  });

  it('returns an empty list when nothing is ransomware-linked', () => {
    expect(topRansomwareTargets([kev({})], 5)).toEqual([]);
  });
});

describe('recentlyAddedKev', () => {
  it('returns the newest entries first, capped at n', () => {
    const catalog = [
      kev({ cveId: 'old', added: '2025-01-01T00:00:00' }),
      kev({ cveId: 'new', added: '2026-06-01T00:00:00' }),
      kev({ cveId: 'mid', added: '2026-01-01T00:00:00' }),
    ];
    expect(recentlyAddedKev(catalog, 2).map((k) => k.cveId)).toEqual(['new', 'mid']);
  });

  it('does not mutate the input array', () => {
    const catalog = [
      kev({ cveId: 'a', added: '2025-01-01T00:00:00' }),
      kev({ cveId: 'b', added: '2026-01-01T00:00:00' }),
    ];
    recentlyAddedKev(catalog, 2);
    expect(catalog.map((k) => k.cveId)).toEqual(['a', 'b']);
  });
});
