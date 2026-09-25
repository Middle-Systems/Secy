package net.jdesive.secy.model.component;

import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.IdentityConflictType;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * {@code GET /sbom/{sbomId}/components/{componentId}/identity} — the read path for the
 * {@code @JsonIgnore}d {@code SBOMComponent.identifiers}/{@code identityConflicts} collections
 * (M1c, ROADMAP.md — "Canonical component identity"). Built by
 * {@code ComponentIdentityService#describe}.
 */
public record ComponentIdentityResponse(UUID componentId, UUID sbomId, String name, String version, String purl,
                                        String identityKey, IdentityConfidence identityConfidence,
                                        List<IdentifierView> identifiers, List<HashView> hashes,
                                        List<ConflictView> conflicts, ComponentProvenance provenance) {

    public record IdentifierView(SecondaryIdentifierType type, String value, String declaredName,
                                 String declaredVersion, String source) {
    }

    public record HashView(String algorithm, String value) {
    }

    public record ConflictView(IdentityConflictType type, SecondaryIdentifierType identifierType,
                               String identifierValue, UUID otherComponentId, String otherIdentityKey,
                               String detail, LocalDateTime detectedAt) {
    }

}
