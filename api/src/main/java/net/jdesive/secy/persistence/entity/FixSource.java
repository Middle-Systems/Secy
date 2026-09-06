package net.jdesive.secy.persistence.entity;

/**
 * Where {@code VulnerabilityAlert.fixedVersions} came from, in descending order of trust.
 *
 * <p>Only {@link #SCANNER} is produced in Phase 1 — an infrastructure scanner (Trivy/Grype) that
 * reported a {@code FixedVersion} alongside the finding. {@link #OSV} and {@link #CPE_RANGE} are
 * populated by the Phase 2 correlation rework.
 */
public enum FixSource {

    /** OSV advisory {@code fixed} event — authoritative for open-source packages. */
    OSV,

    /** Reported verbatim by the scanner that produced the finding. */
    SCANNER,

    /** Derived from an NVD CPE range's {@code versionEndExcluding}; approximate. */
    CPE_RANGE

}
