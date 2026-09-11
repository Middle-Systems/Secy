package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.entity.MatchConfidence;

/**
 * One "this component is affected by this CVE" verdict, before it becomes a
 * {@code VulnerabilityAlert}.
 *
 * <p>Both correlation paths emit these, so {@code CorrelationService} can de-duplicate and persist
 * without caring which produced them.
 *
 * @param cveId      the CVE this match resolves to; the funnel is CVE-driven, so a match that
 *                   cannot name one is dropped upstream
 * @param confidence how firmly the component was identified
 * @param fix        what the matching source says about a fix
 * @param evidence   short human-readable provenance for logs — the OSV id, or the CPE criteria
 */
public record CorrelationMatch(String cveId, MatchConfidence confidence, FixResolution fix, String evidence) {

    /**
     * The stronger of two matches for the same {@code (component, CVE)} pair.
     *
     * <p>Confidence decides, using the enum's declaration order (strongest first). The fix data is
     * merged independently — a weaker match that names a fixed version should not lose that version
     * just because a stronger one had nothing to say.
     */
    public static CorrelationMatch best(CorrelationMatch a, CorrelationMatch b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        CorrelationMatch stronger = a.confidence().ordinal() <= b.confidence().ordinal() ? a : b;
        FixResolution fix = FixResolution.best(a.fix(), b.fix());
        return new CorrelationMatch(stronger.cveId(), stronger.confidence(), fix, stronger.evidence());
    }

}
