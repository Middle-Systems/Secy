/**
 * Local type extensions for the Product Catalog view.
 *
 * `GET /api/products` returns only `id, name, description, createdAt, sboms`
 * (see the note in `src/api/types.ts`). The roll-up counters the cards render —
 * active-SBOM status, total findings, actionable findings — are derived
 * client-side in `product.derive.ts`. `DerivedProduct` is the shape after that
 * derivation: every field the view reads is present and non-optional.
 */
import type { Product, SBOM, VulnerabilityAlert } from '@/api/types';

/** Display bucket for an SBOM's scan status, as shown on the product card badge. */
export type SbomStatusDisplay = 'Scanning' | 'Complete' | 'Failed' | 'Unknown';

/**
 * A {@link Product} with the SBOM-derived roll-ups resolved. Produced by
 * `deriveProduct`. Unlike the wire `Product`, the counters here are always
 * numbers (0 when there is no active SBOM) so the view never renders
 * `undefined`.
 */
export interface DerivedProduct extends Product {
  /** The product's active SBOM, or `undefined` when none is active yet. */
  activeSbom?: SBOM;
  activeSbomId?: string;
  activeSbomStatus?: string;
  /** Human display bucket for {@link activeSbomStatus}. */
  activeSbomStatusDisplay: SbomStatusDisplay;
  /** ISO-8601 string; `undefined` until the first scan of the active SBOM finishes. */
  lastScanned?: string;
  /** Total vulnerability alerts across the active SBOM's components. */
  vulnerabilityCount: number;
  /** Alerts that are KEV-listed OR have EPSS > 0.1. */
  actionableCount: number;
}

/** A component grouping of alerts, used by the vulnerability-details modal. */
export interface AlertGroup {
  component: VulnerabilityAlert['component'];
  alerts: VulnerabilityAlert[];
  /** Alerts in this group that satisfy the actionable predicate. */
  actionableCount: number;
}
