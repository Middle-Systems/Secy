package net.jdesive.secy.persistence.entity;

/** The feed an {@link Job} pulls. One background job per value may be active at a time. */
public enum JobType {

    /** NIST National Vulnerability Database CVE records. */
    NVD,

    /** FIRST Exploit Prediction Scoring System scores. */
    EPSS,

    /** CISA Known Exploited Vulnerabilities catalog. */
    KEV

}
