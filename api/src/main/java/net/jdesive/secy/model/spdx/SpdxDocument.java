package net.jdesive.secy.model.spdx;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

/**
 * An SPDX JSON document, 2.2 or 2.3.
 *
 * <p>Only the fields Secy correlates on are bound. See {@code SpdxNormalizer} for the
 * constructs deliberately left unparsed.
 */
@Data
public class SpdxDocument {

    /** {@code "SPDX-2.2"} or {@code "SPDX-2.3"}. Its presence is what identifies the format. */
    private String spdxVersion;

    @JsonProperty("SPDXID")
    private String spdxId;

    private String name;

    private String dataLicense;

    private SpdxCreationInfo creationInfo;

    /** SPDXIDs of the elements the document describes — the root package(s). */
    private List<String> documentDescribes;

    private List<SpdxPackage> packages;

    private List<SpdxRelationship> relationships;

}
