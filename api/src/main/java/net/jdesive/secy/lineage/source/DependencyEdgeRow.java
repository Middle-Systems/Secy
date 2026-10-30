package net.jdesive.secy.lineage.source;

import java.util.UUID;

/**
 * One resolved {@code sbom_component_dependency} row, as read for lineage planning (M1l). {@code
 * fromRoot} is true when {@code componentId} is the owning SBOM's root/metadata component — the
 * root is never a lineage node, so the planner emits {@code SBOM -[:DEPENDS_ON]-> Component}
 * instead of {@code Component -[:DEPENDS_ON]-> Component} for those rows.
 */
public record DependencyEdgeRow(UUID sbomId, UUID componentId, UUID dependsOnComponentId, boolean fromRoot) {
}
