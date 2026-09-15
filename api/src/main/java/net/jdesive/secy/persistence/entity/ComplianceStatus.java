package net.jdesive.secy.persistence.entity;

import java.util.Locale;

/**
 * The verdict on one compliance control, or on one check inside it.
 *
 * <h2>Why three values and not a boolean</h2>
 *
 * <p>A benchmark control is not "pass or fail". Trivy only emits a finding for a check it actually
 * evaluated, and a great many CIS Docker controls are manual/operational items it cannot evaluate at
 * all. Collapsing "not evaluated" into {@link #PASS} would let Secy report compliance it has no
 * evidence for, which is the one thing a posture tool must never do; collapsing it into {@link #FAIL}
 * would bury the real failures under noise. So it gets its own value.
 */
public enum ComplianceStatus {

    /** The check ran and the control was satisfied. Trivy {@code "Status": "PASS"}. */
    PASS,

    /**
     * The check ran and the control was violated. Trivy {@code "Status": "FAIL"} — and also a
     * misconfiguration reported with no {@code Status} at all, because Trivy's default output only
     * lists findings, and a listed finding is a failure.
     */
    FAIL,

    /**
     * No evidence either way: the check was excepted ({@code "Status": "EXCEPTION"}), or the control
     * produced no results at all because Trivy has no automated check for it.
     */
    SKIP;

    /**
     * Trivy's {@code Status} string → a status.
     *
     * @param status the raw value; {@code null}/blank means "reported as a finding with no status",
     *               which is a {@link #FAIL}
     */
    public static ComplianceStatus ofFinding(String status) {
        if (status == null || status.isBlank()) {
            return FAIL;
        }
        return switch (status.trim().toUpperCase(Locale.ROOT)) {
            case "PASS", "PASSED", "OK" -> PASS;
            case "EXCEPTION", "SKIP", "SKIPPED", "IGNORED" -> SKIP;
            default -> FAIL;
        };
    }

    /**
     * Roll a control's checks up into one verdict: any failure fails the control; otherwise any
     * evaluated check passes it; otherwise there was nothing to go on.
     *
     * @param checks the statuses of the control's reported checks, possibly empty
     */
    public static ComplianceStatus rollUp(Iterable<ComplianceStatus> checks) {
        boolean sawPass = false;
        for (ComplianceStatus check : checks) {
            if (check == FAIL) {
                return FAIL;
            }
            if (check == PASS) {
                sawPass = true;
            }
        }
        return sawPass ? PASS : SKIP;
    }

}
