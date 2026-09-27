package net.jdesive.secy.model.cyclonedx;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class CycloneDXMetadata {

    private Date timestamp;

    private CycloneDXToolComponent tools;

    private CycloneDXComponent component;

    /** CycloneDX 1.5+ (M1e). See {@code CycloneDXNormalizer} for the phase → stage mapping. */
    private List<CycloneDXLifecycle> lifecycles;

    /**
     * {@code metadata.authors[]} (M1h) — OrganizationalContact entries {@code {name,email,phone}},
     * who created the SBOM DATA (never the tool). Bound as a raw tree, same reasoning as
     * {@link CycloneDXComponent#getCryptoProperties()}.
     */
    private JsonNode authors;

    /**
     * CycloneDX 1.6 {@code metadata.manufacturer} (M1h) — "the organization that created the BOM".
     * Deliberately distinct from 1.5's {@code metadata.manufacture} (who manufactured the described
     * component — the product, not the SBOM author) and from {@code metadata.supplier} (supplier of
     * the described product) — neither of those is bound here or read as an author source.
     */
    private JsonNode manufacturer;

}
