package net.jdesive.secy.service.finding;

import net.jdesive.secy.model.finding.FindingFix;
import net.jdesive.secy.model.finding.FixKind;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;

/**
 * Pure, static "what would fix this finding" logic (M1k — ROADMAP.md's "Role-based views" §5,
 * "Concrete fix"). <b>Honest note: only the vulnerability fix is data-derived</b>, straight off
 * {@code VulnerabilityAlert.fixState}/{@code fixedVersions}/{@code fixSource} — the other four
 * finding types get a fixed, templated piece of guidance text per type, because none of them carry
 * a "here is the specific remediation" field today (a compromise finding says nothing about which
 * clean version to roll back to, a lifecycle-drift finding has no single target state, a quantum
 * finding names an algorithm family but not a replacement library, and an SBOM-quality finding's
 * fix is "regenerate a better document", not a per-component action).
 */
public final class FindingFixAdvisor {

    private FindingFixAdvisor() {
    }

    /** The only data-derived fix in this class — everything else below is a fixed template. */
    public static FindingFix forVulnerability(FixState fixState, String fixedVersions, FixSource fixSource,
                                                String componentName, String componentVersion) {
        String component = componentName == null ? "this component" : componentName;
        String version = componentVersion == null ? "its current version" : componentVersion;

        if (fixState == FixState.FIXED) {
            String target = fixedVersions == null || fixedVersions.isBlank() ? "a fixed version" : fixedVersions;
            String guidance = "Upgrade " + component + " from " + version + " to " + target;
            return new FindingFix(FixKind.UPGRADE, fixedVersions, fixSource, guidance);
        }
        if (fixState == FixState.NO_FIX) {
            String guidance = "No fixed version is available yet for " + component + " " + version
                    + " — track the upstream advisory or add a compensating control.";
            return new FindingFix(FixKind.NO_FIX_AVAILABLE, null, null, guidance);
        }
        String guidance = "No fix information is available yet for " + component + " " + version + ".";
        return new FindingFix(FixKind.UNKNOWN, null, null, guidance);
    }

    public static FindingFix forCompromise() {
        return new FindingFix(FixKind.INVESTIGATE_COMPROMISE, null, null,
                "Investigate how this known-bad package/indicator entered the build, then remove or "
                        + "replace it — there is no \"upgrade\" for a compromise, only removal and root-cause review.");
    }

    public static FindingFix forLifecycleDrift() {
        return new FindingFix(FixKind.RECONCILE_LIFECYCLE, null, null,
                "Reconcile the diverging Source/Build/Analyzed/Deployed SBOMs so they describe the same "
                        + "component set — regenerate the stale stage's SBOM or investigate why they disagree.");
    }

    public static FindingFix forQuantumVulnerable() {
        return new FindingFix(FixKind.MIGRATE_CRYPTO, null, null,
                "Migrate off this Shor-vulnerable algorithm to a post-quantum or hybrid alternative "
                        + "before a cryptographically-relevant quantum computer makes it exploitable.");
    }

    public static FindingFix forSbomQuality() {
        return new FindingFix(FixKind.IMPROVE_SBOM, null, null,
                "Regenerate this SBOM with better tooling/config so it covers supplier, name, version, "
                        + "unique identifiers and dependency relationships per component (NTIA minimum elements).");
    }

}
