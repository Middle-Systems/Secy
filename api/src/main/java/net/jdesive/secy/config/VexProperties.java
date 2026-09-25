package net.jdesive.secy.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code secy.vex.*} — VEX upload/parsing limits (M1f). The default is repeated in the test
 * properties file since it replaces, not merges with, the main one.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.vex")
public class VexProperties {

    /** {@code POST /vex} rejects a body over this size with a 413, before it is parsed at all. */
    private long maxDocumentBytes = 10_485_760L;

    /** Jackson {@code StreamReadConstraints.maxNestingDepth} for the VEX document parser's own {@code ObjectMapper}. */
    private int maxNestingDepth = 64;

    /** A document emitting (skipped + emitted) more than this many statements is rejected outright. */
    private int maxStatements = 100_000;

    /** CSAF {@code product_tree} branch recursion limit — exceeding it rejects the document. */
    private int maxBranchDepth = 32;

}
