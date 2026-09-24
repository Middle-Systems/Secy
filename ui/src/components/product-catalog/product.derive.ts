/**
 * SBOM-derived roll-ups for the Product Catalog.
 *
 * `GET /api/products` does not serialize the counters the cards show, so they
 * are computed here from `product.sboms`. This is a direct port of the Angular
 * `ProductCatalogComponent.loadProducts` / `SbomHistoryModalComponent`
 * reductions — kept pure and unit-tested so the view stays declarative.
 *
 * "Actionable" is Secy's platform-wide definition: a vulnerability that is
 * CISA-KEV listed OR has an EPSS probability greater than 0.1.
 */
import type { Product, SBOM, VulnerabilityAlert } from '@/api/types';

import type { DerivedProduct, SbomStatusDisplay } from './product.types';

/** EPSS probability above which a finding counts as actionable (strict `>`). */
export const EPSS_ACTIONABLE_THRESHOLD = 0.1;

/** A KEV-listed OR high-EPSS alert. Mirrors the Angular `hasKev || highEpss` filter. */
export function isActionableAlert(alert: VulnerabilityAlert): boolean {
  const hasKev = Boolean(alert.vulnerability?.kev);
  const epss = alert.vulnerability?.epss?.epss ?? 0;
  return hasKev || epss > EPSS_ACTIONABLE_THRESHOLD;
}

/** The product's active SBOM (`active === true`), or `undefined`. */
export function activeSbom(product: Product): SBOM | undefined {
  return product.sboms?.find((sbom) => sbom.active === true);
}

/**
 * Every active SBOM on a product. For a normal product this is at most one (see {@link activeSbom});
 * the "Unassigned" bucket (M1a) deliberately keeps every SBOM it ever receives active, since each
 * one is an unrelated document rather than a version of "the product's" SBOM.
 */
export function activeSboms(product: Product): SBOM[] {
  return (product.sboms ?? []).filter((sbom) => sbom.active === true);
}

/** Every alert across an SBOM's components, flattened. */
export function sbomAlerts(sbom: SBOM | undefined): VulnerabilityAlert[] {
  return (sbom?.components ?? []).flatMap((component) => component.vulnerabilityAlerts ?? []);
}

/** Total vulnerability alerts across an SBOM's components. */
export function countAlerts(sbom: SBOM | undefined): number {
  return sbomAlerts(sbom).length;
}

/** Alerts across an SBOM's components that satisfy {@link isActionableAlert}. */
export function countActionableAlerts(sbom: SBOM | undefined): number {
  return sbomAlerts(sbom).filter(isActionableAlert).length;
}

/** Map a raw SBOM status onto the card's display bucket. */
export function sbomStatusLabel(status: string | null | undefined): SbomStatusDisplay {
  switch (status?.trim().toUpperCase()) {
    case 'PROCESSING':
    case 'SCANNING':
    case 'PENDING':
      return 'Scanning';
    case 'SCANNED':
    case 'COMPLETE':
    case 'COMPLETED':
    case 'DONE':
      return 'Complete';
    case 'FAILED':
    case 'ERROR':
      return 'Failed';
    default:
      return 'Unknown';
  }
}

/** True while some SBOM on the product is still being scanned. */
export function isProductScanning(product: Product): boolean {
  return (product.sboms ?? []).some((sbom) => sbomStatusLabel(sbom.status) === 'Scanning');
}

/**
 * Worst-first roll-up of several SBOMs' status displays, for the "Unassigned" bucket card (M1a),
 * which can have many active SBOMs at once rather than the usual single one.
 */
function aggregateStatusDisplay(statuses: SbomStatusDisplay[]): SbomStatusDisplay {
  if (statuses.includes('Scanning')) return 'Scanning';
  if (statuses.includes('Failed')) return 'Failed';
  if (statuses.includes('Complete')) return 'Complete';
  return 'Unknown';
}

/** Resolve the SBOM-derived roll-ups for one product. */
export function deriveProduct(product: Product): DerivedProduct {
  if (product.unassigned) {
    // The bucket (M1a) can hold many active SBOMs at once — roll up over all of them rather than
    // picking a single "the" active SBOM, which doesn't exist for it.
    const actives = activeSboms(product);
    const lastScanned = actives
      .map((sbom) => sbom.lastScannedAt)
      .filter((value): value is string => Boolean(value))
      .sort()
      .at(-1);
    return {
      ...product,
      activeSbom: undefined,
      activeSbomId: undefined,
      activeSbomStatus: undefined,
      activeSbomStatusDisplay: aggregateStatusDisplay(actives.map((sbom) => sbomStatusLabel(sbom.status))),
      lastScanned,
      vulnerabilityCount: actives.reduce((sum, sbom) => sum + countAlerts(sbom), 0),
      actionableCount: actives.reduce((sum, sbom) => sum + countActionableAlerts(sbom), 0),
    };
  }

  const sbom = activeSbom(product);
  return {
    ...product,
    activeSbom: sbom,
    activeSbomId: sbom?.id,
    activeSbomStatus: sbom?.status,
    activeSbomStatusDisplay: sbomStatusLabel(sbom?.status),
    lastScanned: sbom?.lastScannedAt ?? undefined,
    vulnerabilityCount: countAlerts(sbom),
    actionableCount: countActionableAlerts(sbom),
  };
}

/** Derive a whole list, newest product first. */
export function deriveProducts(products: Product[]): DerivedProduct[] {
  return [...products]
    .map(deriveProduct)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

/**
 * Put the "Unassigned" bucket (M1a) first, keeping every other product in whatever order it
 * arrived in (typically {@link deriveProducts}' newest-first order). Pure — does not mutate.
 */
export function sortProductsUnassignedFirst<T extends { unassigned?: boolean }>(products: T[]): T[] {
  const bucket = products.filter((product) => product.unassigned);
  const rest = products.filter((product) => !product.unassigned);
  return [...bucket, ...rest];
}

/** SBOM history rows, newest upload first. */
export function sbomsByRecency(product: Product): SBOM[] {
  return [...(product.sboms ?? [])].sort(
    (a, b) => new Date(b.uploadDate).getTime() - new Date(a.uploadDate).getTime(),
  );
}

/**
 * Priority sort for the vulnerability-details table: KEV first, then EPSS
 * descending, then CVSS descending. Ported from the Angular `prioritizeAlerts`.
 */
export function prioritizeAlerts(alerts: VulnerabilityAlert[]): VulnerabilityAlert[] {
  return [...alerts].sort((a, b) => {
    const aKev = a.vulnerability?.kev ? 1 : 0;
    const bKev = b.vulnerability?.kev ? 1 : 0;
    if (aKev !== bKev) return bKev - aKev;

    const aEpss = a.vulnerability?.epss?.epss ?? 0;
    const bEpss = b.vulnerability?.epss?.epss ?? 0;
    if (aEpss !== bEpss) return bEpss - aEpss;

    return (b.vulnerability?.cvssScore ?? 0) - (a.vulnerability?.cvssScore ?? 0);
  });
}

/** Group alerts by their owning component, each group prioritized and counted. */
export function groupAlertsByComponent(
  alerts: VulnerabilityAlert[],
): import('./product.types').AlertGroup[] {
  const groups = new Map<string, VulnerabilityAlert[]>();
  for (const alert of alerts) {
    const key = alert.component?.id ?? alert.component?.name ?? 'unknown';
    const bucket = groups.get(key);
    if (bucket) bucket.push(alert);
    else groups.set(key, [alert]);
  }

  return [...groups.values()]
    .map((groupAlerts) => ({
      component: groupAlerts[0].component,
      alerts: prioritizeAlerts(groupAlerts),
      actionableCount: groupAlerts.filter(isActionableAlert).length,
    }))
    .sort((a, b) => {
      if (a.actionableCount !== b.actionableCount) return b.actionableCount - a.actionableCount;
      return b.alerts.length - a.alerts.length;
    });
}
