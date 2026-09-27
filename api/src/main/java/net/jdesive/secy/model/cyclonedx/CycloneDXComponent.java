package net.jdesive.secy.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.List;

@Data
public class CycloneDXComponent {

    private String type;

    @JsonProperty("bom-ref")
    private String bomRef;

    private String name;

    private String group;

    private String version;

    private String description;

    private List<CycloneDXComponentLicense> licenses;

    private String purl;

    /** Optional {@code hashes[]} — the digests Phase 6 matches against the malware-hash corpus. */
    private List<CycloneDXHash> hashes;

    private List<CycloneDXExternalReference> externalReferences;

    /** Optional declared CPE 2.2/2.3 string (M1c) — promoted to a secondary identifier, never folded into {@code identityKey}. */
    private String cpe;

    /** Optional declared SWID tag (M1c) — see {@link CycloneDXSwid}. */
    private CycloneDXSwid swid;

    /**
     * CycloneDX 1.6 {@code cryptoProperties} (M1g). Bound as a raw tree on purpose — see
     * {@code net.jdesive.secy.service.cbom.CryptoPropertiesExtractor}: {@code FAIL_ON_UNKNOWN_PROPERTIES=false}
     * only tolerates unknown keys, not shape mismatches, and real-world CBOM shape drift is common
     * enough that a typed POJO here would risk a 400 for the whole SBOM.
     */
    private JsonNode cryptoProperties;

    /**
     * {@code component.supplier} (M1h) — an OrganizationalEntity {@code {name, url[], contact[]}}.
     * Bound as a raw tree, same reasoning as {@link #cryptoProperties}: only {@code name} is ever
     * read (see {@code CycloneDXNormalizer#organizationName}), so a typed POJO would risk rejecting a
     * document whose {@code supplier} shape drifts in a field Secy never reads anyway.
     */
    private JsonNode supplier;

}
