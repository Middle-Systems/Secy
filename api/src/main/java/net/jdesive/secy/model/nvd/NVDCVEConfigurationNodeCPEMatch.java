package net.jdesive.secy.model.nvd;

import lombok.Getter;

/**
 * One {@code configurations[].nodes[].cpeMatch[]} entry of an NVD CVE record.
 *
 * <p>Field names match the NVD JSON exactly, so Jackson binds them with no annotations. The four
 * version attributes are optional in the payload and absent on rows that name a single concrete
 * version; when present they are the authoritative affected range, and the {@code version} field
 * inside {@link #criteria} is a wildcard.
 */
@Getter
public class NVDCVEConfigurationNodeCPEMatch {

    private boolean vulnerable;

    private String criteria;

    private String matchCriteriaId;

    /** Inclusive lower bound of the affected range. */
    private String versionStartIncluding;

    /** Exclusive lower bound of the affected range. */
    private String versionStartExcluding;

    /** Inclusive upper bound of the affected range. */
    private String versionEndIncluding;

    /** Exclusive upper bound — the first unaffected version, i.e. the fix. */
    private String versionEndExcluding;

}
