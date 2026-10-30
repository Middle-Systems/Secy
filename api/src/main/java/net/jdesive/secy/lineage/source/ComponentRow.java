package net.jdesive.secy.lineage.source;

import net.jdesive.secy.persistence.entity.IdentityConfidence;

import java.util.UUID;

/**
 * One non-root {@code sbom_component} row belonging to an active SBOM, as read for lineage
 * planning. The reader excludes the SBOM's root/metadata component (see
 * {@code net.jdesive.secy.lineage.LineageSourceReader}).
 */
public record ComponentRow(UUID id, UUID sbomId, String name, String version, String purl,
                            String identityKey, String type, IdentityConfidence identityConfidence) {
}
