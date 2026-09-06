package net.jdesive.secy.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DashboardStats {

    /* ------------------------------------------------------------------ */
    /* Global feed health — counts over the whole CVE / KEV / EPSS tables. */
    /* ------------------------------------------------------------------ */

    private long globalSyncs;      // CVEs + KEVs + EPSS updated in last 7d
    private long activeKevCount;   // Total size of KEV table
    private long highEpssCount;    // EPSS > 0.36 updated in last 7d
    private long accessibleCount;  // AV:N and AC:L in global CVE table

    private long globalCrit;
    private long globalHigh;
    private long globalMed;
    private long globalLow;

    /* ------------------------------------------------------------------ */
    /* Your posture — counts over alerts that cleared the funnel.          */
    /* ------------------------------------------------------------------ */

    /** Alerts with {@code actionable = true}. The headline number. */
    private long openActionableCount;

    /**
     * By funnel reason. These <b>overlap</b>: an alert with reason {@code KEV_AND_EPSS_HIGH} is
     * counted in both, so each tile reads as "how many are KEV-listed" / "how many have high EPSS"
     * rather than as a partition of {@link #openActionableCount}.
     */
    private long actionableKevCount;
    private long actionableEpssCount;

    /** Actionable alerts by the CVE's NVD severity band. Unscored CVEs fall into none of them. */
    private long actionableCrit;
    private long actionableHigh;
    private long actionableMed;
    private long actionableLow;

    /** Actionable alerts with a known fixed version ({@code fixState = FIXED}). */
    private long actionableWithFixCount;
    /** Actionable alerts with no fixed version to offer — {@code NO_FIX} or {@code UNKNOWN}. */
    private long actionableNoFixCount;

    /** Actionable alerts by exploit maturity. These four <b>do</b> partition {@link #openActionableCount}. */
    private long actionableExploitNone;
    private long actionableExploitPoc;
    private long actionableExploitWeaponized;
    private long actionableExploitInTheWild;

    /** Actionable alerts whose CISA KEV remediation deadline has already passed. */
    private long pastKevDueCount;

    /** Actionable alerts generated in the last 7 days — the trend arrow. */
    private long actionableCreatedLast7d;
}
