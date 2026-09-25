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
import type { Product, SBOM, SbomLifecycleStage, VulnerabilityAlert } from '@/api/types';

import type { DerivedProduct, SbomStatusDisplay } from './product.types';

/** EPSS probability above which a finding counts as actionable (strict `>`). */
export const EPSS_ACTIONABLE_THRESHOLD = 0.1;

/** A KEV-listed OR high-EPSS alert. Mirrors the Angular `hasKev || highEpss` filter. */
export function isActionableAlert(alert: VulnerabilityAlert): boolean {
  const hasKev = Boolean(alert.vulnerability?.kev);
  const epss = alert.vulnerability?.epss?.epss ?? 0;
  return hasKev || epss > EPSS_ACTIONABLE_THRESHOLD;
}

/**
 * Downstream-most first (M1e): a normal product can now hold several simultaneously-active stage
 * SBOMs (Source/Build/Analyzed/Deployed), so "the" active SBOM a single-SBOM view shows must be
 * picked deterministically rather than by array order (`Array.find` on an API-ordered array is not a
 * stable "current" pick once more than one SBOM can be active). An unstaged SBOM ranks last — a
 * stage-less upload is the pre-M1e legacy slot, never simultaneously active alongside a staged one.
 */
const STAGE_RANK: Record<SbomLifecycleStage, number> = {
  DEPLOYED: 4,
  ANALYZED: 3,
  BUILD: 2,
  SOURCE: 1,
};

function stageRank(sbom: SBOM): number {
  return sbom.lifecycleStage ? STAGE_RANK[sbom.lifecycleStage] : 0;
}

/**
 * The product's single "headline" active SBOM: highest lifecycle stage first (DEPLOYED > ANALYZED >
 * BUILD > SOURCE > unstaged), ties broken by the newest `uploadDate`. `undefined` when none is
 * active. See {@link activeSboms} for the full set a staged product may have active at once.
 */
export function activeSbom(product: Product): SBOM | undefined {
  const actives = activeSboms(product);
  if (actives.length === 0) return undefined;
  return [...actives].sort((a, b) => {
    const rankDiff = stageRank(b) - stageRank(a);
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.uploadDate).getTime() - new Date(a.uploadDate).getTime();
  })[0];
}

/**
 * Every active SBOM on a product. For a normal product this can now be more than one (M1e — at most
 * one per lifecycle stage slot); the "Unassigned" bucket (M1a) deliberately keeps every SBOM it ever
 * receives active, since each one is an unrelated document rather than a version of "the product's"
 * SBOM or a stage of one pipeline.
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

  // M1e: a normal (non-bucket) product can now have several simultaneously-active stage SBOMs.
  // `sbom` below is still the single deterministic "headline" one the card links to, but the
  // counters and status roll up over every active stage's components — each alert attaches to
  // exactly one component row, so this is an unchanged result when there is only one active SBOM.
  const actives = activeSboms(product);
  const sbom = activeSbom(product);
  const statuses = actives.map((s) => sbomStatusLabel(s.status));
  const lastScanned = actives
    .map((s) => s.lastScannedAt)
    .filter((value): value is string => Boolean(value))
    .sort()
    .at(-1);

  return {
    ...product,
    activeSbom: sbom,
    activeSbomId: sbom?.id,
    activeSbomStatus: sbom?.status,
    activeSbomStatusDisplay: actives.length > 1 ? aggregateStatusDisplay(statuses) : sbomStatusLabel(sbom?.status),
    lastScanned,
    vulnerabilityCount: actives.reduce((sum, s) => sum + countAlerts(s), 0),
    actionableCount: actives.reduce((sum, s) => sum + countActionableAlerts(s), 0),
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
