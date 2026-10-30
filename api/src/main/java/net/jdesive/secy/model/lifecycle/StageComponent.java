package net.jdesive.secy.model.lifecycle;

import java.util.UUID;

/**
 * One component row of a lifecycle-stage SBOM, as {@code LifecycleDiffer} needs it — the projection
 * {@code SBOMComponentRepository#findStageComponents} returns (M1e).
 *
 * @param componentId the {@code sbom_component} row id — used only for deterministic tie-breaking
 *                    when grouping by identity, never for identity itself
 * @param identityKey the component's stable identity (see {@code ComponentIdentity}); rows with a
 *                    null identity key are dropped before diffing
 * @param name        the declared component name
 * @param version     the declared version string, as-is (un-normalised — {@code LifecycleDiffer}
 *                    normalises it)
 * @param purl        the declared PURL, when present
 */
public record StageComponent(UUID componentId, String identityKey, String name, String version, String purl) {
}
