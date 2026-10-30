package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

/**
 * A CycloneDX component's {@code swid} object (M1c). Only the identity fields
 * {@code net.jdesive.secy.model.component.SecondaryIdentifiers} actually reads are bound — {@code tagVersion}/{@code patch}/{@code url}/the {@code text} attachment
 * are deliberately left out, not just unread: {@code FAIL_ON_UNKNOWN_PROPERTIES=false} silently
 * drops an unbound field, but a *bound* field with the wrong JSON type (schema-invalid, but real
 * producers do this — e.g. {@code tagVersion} as a string, {@code patch} as a non-boolean, {@code url}
 * as an object) fails the whole document, which would reverse this parser's lenient-by-design
 * contract (see {@code SbomParser}'s Javadoc) for three fields nothing downstream ever consults.
 */
@Data
public class CycloneDXSwid {

    private String tagId;

    private String name;

    private String version;

}
