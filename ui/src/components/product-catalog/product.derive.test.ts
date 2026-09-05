import { describe, expect, it } from 'vitest';

import type {
  EPSS,
  KEV,
  Product,
  SBOM,
  SBOMComponent,
  Vulnerability,
  VulnerabilityAlert,
} from '@/api/types';

import {
  activeSbom,
  countActionableAlerts,
  countAlerts,
  deriveProduct,
  deriveProducts,
  EPSS_ACTIONABLE_THRESHOLD,
  groupAlertsByComponent,
  isActionableAlert,
  isProductScanning,
  prioritizeAlerts,
  sbomsByRecency,
  sbomStatusLabel,
} from './product.derive';

/* ------------------------------------------------------------------ */
/* fixtures                                                            */
/* ------------------------------------------------------------------ */

const kev = (cveId = 'CVE-K'): KEV => ({ cveId }) as unknown as KEV;
const epss = (score: number): EPSS => ({ epss: score }) as unknown as EPSS;

function vuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'CVE-0000-0000',
    description: 'test',
    baseSeverity: 'HIGH',
    cvssScore: 7.5,
    exploitabilityScore: 1,
    impactScore: 1,
    published: '2026-01-01T00:00:00',
    lastModified: '2026-01-01T00:00:00',
    ...overrides,
  };
}

function alert(id: string, v: Partial<Vulnerability>, componentId = 'c1'): VulnerabilityAlert {
  const component = {
    id: componentId,
    name: componentId,
    version: '1.0.0',
    vulnerabilityAlerts: [],
  } as SBOMComponent;
  return { id, component, vulnerability: vuln(v) };
}

function component(id: string, alerts: VulnerabilityAlert[]): SBOMComponent {
  return { id, name: id, version: '1.0.0', vulnerabilityAlerts: alerts };
}

function sbom(overrides: Partial<SBOM> = {}): SBOM {
  return {
    id: 's1',
    format: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    active: true,
    status: 'SCANNED',
    uploadDate: '2026-02-01T00:00:00',
    lastScannedAt: '2026-02-01T01:00:00',
    totalVulnerabilities: 0,
    components: [],
    tools: [],
    ...overrides,
  };
}

function product(overrides: Partial<Product> = {}): Product {
  return {
    id: 'p1',
    name: 'Product 1',
    description: 'desc',
    createdAt: '2026-01-01T00:00:00',
    sboms: [],
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */
/* isActionableAlert                                                   */
/* ------------------------------------------------------------------ */

describe('isActionableAlert', () => {
  it('is actionable when KEV-listed regardless of EPSS', () => {
    expect(
      isActionableAlert(alert('a', { kev: kev('CVE-1') })),
    ).toBe(true);
  });

  it('is actionable when EPSS is strictly greater than 0.1', () => {
    expect(isActionableAlert(alert('a', { epss: epss(0.11) }))).toBe(
      true,
    );
  });

  it('is NOT actionable at exactly the 0.1 threshold', () => {
    expect(
      isActionableAlert(
        alert('a', { epss: epss(EPSS_ACTIONABLE_THRESHOLD) }),
      ),
    ).toBe(false);
  });

  it('is NOT actionable with no KEV and low EPSS', () => {
    expect(isActionableAlert(alert('a', { epss: epss(0.02) }))).toBe(
      false,
    );
  });

  it('is NOT actionable with no enrichment at all', () => {
    expect(isActionableAlert(alert('a', {}))).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* counts                                                              */
/* ------------------------------------------------------------------ */

describe('countAlerts / countActionableAlerts', () => {
  const s = sbom({
    components: [
      component('c1', [
        alert('a1', { kev: kev('CVE-1') }, 'c1'),
        alert('a2', { epss: epss(0.5) }, 'c1'),
        alert('a3', {}, 'c1'),
      ]),
      component('c2', [alert('a4', { epss: epss(0.01) }, 'c2')]),
    ],
  });

  it('countAlerts sums every alert across components', () => {
    expect(countAlerts(s)).toBe(4);
  });

  it('countActionableAlerts counts only KEV or EPSS>0.1', () => {
    expect(countActionableAlerts(s)).toBe(2);
  });

  it('both return 0 for an undefined SBOM', () => {
    expect(countAlerts(undefined)).toBe(0);
    expect(countActionableAlerts(undefined)).toBe(0);
  });

  it('both return 0 for an SBOM with no components', () => {
    expect(countAlerts(sbom({ components: [] }))).toBe(0);
    expect(countActionableAlerts(sbom({ components: [] }))).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/* activeSbom                                                          */
/* ------------------------------------------------------------------ */

describe('activeSbom', () => {
  it('finds the SBOM flagged active', () => {
    const a = sbom({ id: 'old', active: false });
    const b = sbom({ id: 'new', active: true });
    expect(activeSbom(product({ sboms: [a, b] }))?.id).toBe('new');
  });

  it('returns undefined when nothing is active', () => {
    expect(activeSbom(product({ sboms: [sbom({ active: false })] }))).toBeUndefined();
  });

  it('returns undefined when there are no SBOMs', () => {
    expect(activeSbom(product({ sboms: [] }))).toBeUndefined();
  });
});

/* ------------------------------------------------------------------ */
/* sbomStatusLabel                                                     */
/* ------------------------------------------------------------------ */

describe('sbomStatusLabel', () => {
  it('maps processing-ish statuses to Scanning', () => {
    expect(sbomStatusLabel('PROCESSING')).toBe('Scanning');
    expect(sbomStatusLabel('scanning')).toBe('Scanning');
  });

  it('maps scanned-ish statuses to Complete', () => {
    expect(sbomStatusLabel('SCANNED')).toBe('Complete');
    expect(sbomStatusLabel('Complete')).toBe('Complete');
  });

  it('maps failure statuses to Failed', () => {
    expect(sbomStatusLabel('FAILED')).toBe('Failed');
    expect(sbomStatusLabel('error')).toBe('Failed');
  });

  it('falls back to Unknown for anything else or nullish', () => {
    expect(sbomStatusLabel(undefined)).toBe('Unknown');
    expect(sbomStatusLabel('')).toBe('Unknown');
    expect(sbomStatusLabel('WEIRD')).toBe('Unknown');
  });
});

/* ------------------------------------------------------------------ */
/* deriveProduct / deriveProducts                                      */
/* ------------------------------------------------------------------ */

describe('deriveProduct', () => {
  it('rolls up the active SBOM counters', () => {
    const active = sbom({
      id: 'active',
      active: true,
      status: 'PROCESSING',
      lastScannedAt: '2026-03-01T00:00:00',
      components: [
        component('c1', [
          alert('a1', { kev: kev('CVE-1') }),
          alert('a2', {}),
        ]),
      ],
    });
    const stale = sbom({ id: 'stale', active: false, components: [component('x', [alert('z', {})])] });

    const derived = deriveProduct(product({ sboms: [stale, active] }));

    expect(derived.activeSbomId).toBe('active');
    expect(derived.activeSbomStatus).toBe('PROCESSING');
    expect(derived.activeSbomStatusDisplay).toBe('Scanning');
    expect(derived.lastScanned).toBe('2026-03-01T00:00:00');
    expect(derived.vulnerabilityCount).toBe(2);
    expect(derived.actionableCount).toBe(1);
  });

  it('zeroes the counters when there is no active SBOM', () => {
    const derived = deriveProduct(product({ sboms: [sbom({ active: false })] }));
    expect(derived.activeSbom).toBeUndefined();
    expect(derived.vulnerabilityCount).toBe(0);
    expect(derived.actionableCount).toBe(0);
    expect(derived.activeSbomStatusDisplay).toBe('Unknown');
    expect(derived.lastScanned).toBeUndefined();
  });
});

describe('deriveProducts', () => {
  it('sorts newest product first', () => {
    const older = product({ id: 'older', createdAt: '2026-01-01T00:00:00' });
    const newer = product({ id: 'newer', createdAt: '2026-06-01T00:00:00' });
    expect(deriveProducts([older, newer]).map((p) => p.id)).toEqual(['newer', 'older']);
  });

  it('does not mutate the input array', () => {
    const input = [product({ id: 'a' }), product({ id: 'b' })];
    deriveProducts(input);
    expect(input.map((p) => p.id)).toEqual(['a', 'b']);
  });
});

/* ------------------------------------------------------------------ */
/* isProductScanning                                                   */
/* ------------------------------------------------------------------ */

describe('isProductScanning', () => {
  it('is true when any SBOM is mid-scan', () => {
    expect(
      isProductScanning(
        product({ sboms: [sbom({ status: 'SCANNED' }), sbom({ status: 'PROCESSING' })] }),
      ),
    ).toBe(true);
  });

  it('is false when every SBOM has settled', () => {
    expect(
      isProductScanning(product({ sboms: [sbom({ status: 'SCANNED' }), sbom({ status: 'FAILED' })] })),
    ).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* sbomsByRecency                                                      */
/* ------------------------------------------------------------------ */

describe('sbomsByRecency', () => {
  it('orders by uploadDate descending without mutating', () => {
    const a = sbom({ id: 'a', uploadDate: '2026-01-01T00:00:00' });
    const b = sbom({ id: 'b', uploadDate: '2026-05-01T00:00:00' });
    const c = sbom({ id: 'c', uploadDate: '2026-03-01T00:00:00' });
    const input = product({ sboms: [a, b, c] });
    expect(sbomsByRecency(input).map((s) => s.id)).toEqual(['b', 'c', 'a']);
    expect(input.sboms.map((s) => s.id)).toEqual(['a', 'b', 'c']);
  });
});

/* ------------------------------------------------------------------ */
/* prioritizeAlerts / groupAlertsByComponent                           */
/* ------------------------------------------------------------------ */

describe('prioritizeAlerts', () => {
  it('orders KEV first, then EPSS desc, then CVSS desc', () => {
    const kevAlert = alert('kev', { kev: kev('CVE-K'), cvssScore: 1 });
    const highEpss = alert('epssHi', { epss: epss(0.9), cvssScore: 2 });
    const lowEpss = alert('epssLo', { epss: epss(0.2), cvssScore: 2 });
    const cvssOnly = alert('cvss', { cvssScore: 9.8 });

    expect(prioritizeAlerts([cvssOnly, lowEpss, highEpss, kevAlert]).map((a) => a.id)).toEqual([
      'kev',
      'epssHi',
      'epssLo',
      'cvss',
    ]);
  });

  it('does not mutate the input', () => {
    const input = [alert('a', { cvssScore: 1 }), alert('b', { cvssScore: 9 })];
    prioritizeAlerts(input);
    expect(input.map((a) => a.id)).toEqual(['a', 'b']);
  });
});

describe('groupAlertsByComponent', () => {
  it('groups by component and sorts groups by actionable count then size', () => {
    const alerts = [
      alert('a1', {}, 'lib-a'),
      alert('a2', { kev: kev('CVE-1') }, 'lib-b'),
      alert('a3', { epss: epss(0.5) }, 'lib-b'),
      alert('a4', {}, 'lib-a'),
      alert('a5', {}, 'lib-a'),
    ];
    const groups = groupAlertsByComponent(alerts);
    expect(groups.map((g) => g.component.id)).toEqual(['lib-b', 'lib-a']);
    expect(groups[0].actionableCount).toBe(2);
    expect(groups[1].alerts.length).toBe(3);
  });
});
