package net.jdesive.secy.model.spdx;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

/**
 * One entry of an SPDX document's {@code packages[]} — the SPDX analogue of a CycloneDX component.
 *
 * <p>SPDX's license fields are <b>expressions</b>, not identifiers: {@code "MIT"} but also
 * {@code "(MIT OR Apache-2.0)"} and the two sentinels {@code NOASSERTION} / {@code NONE}. The
 * normalizer keeps a real expression verbatim and drops the sentinels.
 */
@Data
public class SpdxPackage {

    @JsonProperty("SPDXID")
    private String spdxId;

    private String name;

    /** The version. Absent for a package whose version genuinely is not known. */
    private String versionInfo;

    private String description;

    private String summary;

    private String supplier;

    private String downloadLocation;

    private String licenseConcluded;

    private String licenseDeclared;

    /** SPDX 2.3 only. {@code LIBRARY} / {@code APPLICATION} / {@code CONTAINER} / … */
    private String primaryPackagePurpose;

    /** Where a PURL lives in SPDX: {@code referenceType: "purl"}, locator {@code "pkg:..."}. */
    private List<SpdxExternalRef> externalRefs;

}
