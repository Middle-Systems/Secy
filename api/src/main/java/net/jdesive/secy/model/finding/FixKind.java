package net.jdesive.secy.model.finding;

/**
 * The shape of "what would fix this finding" (M1k — ROADMAP.md's "Role-based views" §5, "Concrete
 * fix"). Only {@link #UPGRADE}/{@link #NO_FIX_AVAILABLE}/{@link #UNKNOWN} are data-derived, straight
 * off {@code VulnerabilityAlert.fixState}; the other four are fixed, templated guidance per finding
 * type — see {@code FindingFixAdvisor}'s class Javadoc for why only vulnerabilities get a real
 * data-derived answer today.
 */
public enum FixKind {

    /** A fixed version is known — {@code VulnerabilityAlert.fixState == FIXED}. */
    UPGRADE,

    /** The upstream project has published no fix yet — {@code fixState == NO_FIX}. */
    NO_FIX_AVAILABLE,

    /** Nothing has told us either way — {@code fixState == UNKNOWN} (or null). */
    UNKNOWN,

    /** A {@code CompromiseFinding} — there is no "fix", only investigation and removal. */
    INVESTIGATE_COMPROMISE,

    /** A {@code LifecycleDriftFinding} — reconcile the diverging Source/Build/Analyzed/Deployed SBOMs. */
    RECONCILE_LIFECYCLE,

    /** A {@code QuantumVulnerabilityFinding} — migrate off the Shor-vulnerable algorithm. */
    MIGRATE_CRYPTO,

    /** An {@code SbomQualityFinding} — improve the SBOM's NTIA minimum-elements coverage. */
    IMPROVE_SBOM

}
