package net.jdesive.secy.service.sbom;

/**
 * No {@code sbom_component} exists with the given id under the given SBOM id — either id is wrong,
 * or the component belongs to a different SBOM (M1c's identity endpoint deliberately scopes its
 * lookup by both, see {@code SBOMComponentRepository#findByIdAndSbomId}). Mapped to {@code 404} by
 * {@code SBOMController}.
 */
public class ComponentNotFoundException extends RuntimeException {
    public ComponentNotFoundException(String message) {
        super(message);
    }
}
