package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

/**
 * A CycloneDX component's {@code swid} object (M1c). Only the identity fields are bound — the
 * {@code text} attachment (the embedded/linked SWID tag XML itself) is not, and an unknown field is
 * silently ignored by {@code SbomParser}'s {@code FAIL_ON_UNKNOWN_PROPERTIES=false} configuration.
 */
@Data
public class CycloneDXSwid {

    private String tagId;

    private String name;

    private String version;

    private Integer tagVersion;

    private Boolean patch;

    private String url;

}
