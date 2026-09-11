package net.jdesive.secy.model.asset;

import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;

/**
 * One package a scanner reported, plus where in the asset it was found.
 *
 * <p>The package itself is a plain {@link NormalizedComponent} — the <em>same</em> record both SBOM
 * parsers produce, not a parallel scanner model. That is the point: correlation must not be able to
 * tell a {@code lodash 4.17.20} read out of a CycloneDX document from one Grype found in an image,
 * because it is the same dependency with the same advisories and the same fix.
 *
 * <p>What a scan carries and an SBOM does not is <em>location</em> — which layer introduced the
 * package, which manifest declared it, which scan target it belonged to. That lives here rather than
 * on {@code NormalizedComponent}, so the shared parse target stays free of fields only one producer
 * can fill.
 *
 * @param component   the package, in the shared normalized shape
 * @param source      which scanner reported it (or {@code DECLARED_CPE} for an operator-declared one)
 * @param scanTarget  Trivy's {@code Results[].Target} / Grype's scan source
 * @param packagePath Trivy's {@code PkgPath} / Grype's first {@code locations[].path}
 * @param layer       Trivy's {@code Layer.DiffID} / Grype's {@code locations[].layerID}
 */
public record ScannedPackage(NormalizedComponent component,
                             AssetComponentSource source,
                             String scanTarget,
                             String packagePath,
                             String layer) {

    /** The identity this package carries across re-scans of its asset. */
    public String identityKey() {
        return component.identityKey();
    }

}
