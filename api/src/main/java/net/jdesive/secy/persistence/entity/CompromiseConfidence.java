package net.jdesive.secy.persistence.entity;

/**
 * How firmly Secy believes the operator is actually shipping the known-bad thing.
 *
 * <h2>The rule, in one sentence</h2>
 *
 * <p><b>{@link #CONFIRMED} when the feed's own statement covers this exact artefact with no
 * inference; {@link #LIKELY} when reaching the artefact needed an inference; {@link #INVESTIGATE}
 * when the evidence has gone stale.</b>
 *
 * <p>Deliberately <em>not</em> {@code MatchConfidence}. That enum answers "is this really my
 * component?" for a CVE correlation and its bands ({@code EXACT}/{@code RANGE}/{@code HEURISTIC})
 * describe how a version range was evaluated. This one answers "how sure are we that you are
 * compromised", which has a third state — decayed — that has no counterpart there, and which the IOC
 * aging job writes. Sharing one enum would have made {@code HEURISTIC} and "the IOC is 18 months
 * old" indistinguishable.
 *
 * <p>Declaration order is the display order and the sort order: see
 * {@code CompromiseService}'s confidence rank.
 */
public enum CompromiseConfidence {

    /**
     * The feed named this artefact. A SHA-256 equality against a MalwareBazaar sample, a
     * malicious-package record that enumerates the exact version in {@code affected[].versions[]},
     * or one that asserts the whole package is malicious (an unbounded {@code introduced: "0"} range
     * with no fix and no last-affected bound — the normal shape for a malicious publish).
     */
    CONFIRMED,

    /**
     * The match required an inference. The component's version fell inside a <em>bounded</em> stated
     * range, or the package name matched but the component declared no version to test at all.
     */
    LIKELY,

    /**
     * The evidence has decayed past {@code secy.compromise.ioc-stale-after} — the IOC has not been
     * re-observed by its feed within the window. The finding is <b>kept, never deleted</b>: it is
     * still real history and still worth a look, it just no longer carries a live claim.
     *
     * @see net.jdesive.secy.service.CompromiseAgingService
     */
    INVESTIGATE

}
