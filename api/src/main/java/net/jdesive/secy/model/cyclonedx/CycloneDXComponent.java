package net.jdesive.secy.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonProperty;
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

}
