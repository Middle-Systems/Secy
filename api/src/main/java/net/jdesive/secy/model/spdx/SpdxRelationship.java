package net.jdesive.secy.model.spdx;

import lombok.Data;

/**
 * An SPDX {@code relationships[]} entry.
 *
 * <p>Secy reads exactly one relationship type — {@code DESCRIBES} — to find the document's root
 * package. The rest of the graph ({@code DEPENDS_ON}, {@code CONTAINS}, {@code GENERATED_FROM}, …) is
 * bound but unused; see {@code SpdxNormalizer} for why.
 */
@Data
public class SpdxRelationship {

    private String spdxElementId;

    private String relationshipType;

    private String relatedSpdxElement;

}
