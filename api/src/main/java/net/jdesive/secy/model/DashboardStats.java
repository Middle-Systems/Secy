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

    /* ------------------------------------------------------------------ */
    /* Supply-chain compromise (Phase 6).                                 */
    /* ------------------------------------------------------------------ */

    /**
     * Active {@code compromise_finding} rows — the "you are shipping something known-bad" tile.
     *
     * <p><b>Not</b> included in {@link #openActionableCount}, and deliberately so. Every other
     * actionable number on this dashboard is a count of {@code vulnerability_alert} rows, and folding
     * a different table into that headline would break the one invariant the rest of the block
     * relies on — that the severity, fix, exploit-maturity and KEV breakdowns sum to (or partition)
     * it. A compromise finding has no severity band to count, no fix state and no exploit maturity,
     * so it would land in the headline and in none of the breakdowns, and every tile below would
     * silently stop adding up. It gets its own tile instead, which is also how the roadmap describes
     * it ("Dashboard gains a 'compromise findings' tile").
     *
     * <p>{@code GET /actionable}'s {@code totalElements} <em>does</em> include both, because that is
     * one merged list rather than a set of roll-ups. So the screen's row count is
     * {@code openActionableCount + compromiseFindingCount}.
     */
    private long compromiseFindingCount;

    /**
     * The confirmed subset — the feed named this exact artefact. These are the ones where there is
     * nothing to weigh up.
     */
    private long compromiseConfirmedCount;

    /**
     * The decayed subset: findings IOC aging has demoted to {@code INVESTIGATE} because their
     * indicator has not been re-observed within {@code secy.compromise.ioc-stale-after}. Still
     * counted in {@link #compromiseFindingCount} — evidence is never deleted, only ranked lower.
     */
    private long compromiseInvestigateCount;

    /** Compromise findings raised in the last 7 days — the trend arrow for the tile. */
    private long compromiseCreatedLast7d;
}
