package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.version.VersionRange;
import net.jdesive.secy.correlation.version.VersionScheme;
import net.jdesive.secy.correlation.version.VersionSchemes;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The primary correlation path: PURL in, OSV advisories out.
 *
 * <p>OSV is package-native. It indexes by ecosystem and package name — the same two things a PURL
 * carries — and it states affected version ranges <em>and the version that fixed them</em>. There is
 * no name guessing and no vendor inference, which is why this path runs first and why the CPE
 * fallback only runs when OSV has never heard of the package at all.
 *
 * <h2>Coverage, not hits</h2>
 *
 * <p>{@link OsvMatchResult#covered()} is the important distinction. "OSV holds advisories for
 * lodash but none of them match 4.17.21" is a <b>positive statement that the component is clean</b>,
 * and falling through to CPE name-matching after it would reintroduce exactly the false positives
 * this phase exists to remove. "OSV has never heard of this package" is a gap, and the fallback is
 * the right answer there.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OsvMatcher {

    private final OsvAdvisoryRepository advisoryRepository;

    /**
     * @param covered whether OSV holds <em>any</em> advisory for this package — see the class note
     * @param matches the advisories whose affected versions include the component's version
     */
    public record OsvMatchResult(boolean covered, List<CorrelationMatch> matches) {

        static final OsvMatchResult NOT_COVERED = new OsvMatchResult(false, List.of());
    }

    /**
     * Evaluate a component against the OSV mirror.
     *
     * <p>Returns {@link OsvMatchResult#NOT_COVERED} — which sends the component to the CPE
     * fallback — when the coordinate has no OSV ecosystem, when it carries no version to test, or
     * when the mirror holds nothing for the package.
     */
    @Transactional(readOnly = true)
    public OsvMatchResult match(ComponentCoordinate coordinate) {
        if (coordinate == null || !coordinate.hasEcosystem() || !coordinate.isVersioned()) {
            return OsvMatchResult.NOT_COVERED;
        }

        List<OsvAdvisory> advisories = advisoryRepository.findForPackage(coordinate.ecosystem(), coordinate.name());
        if (advisories.isEmpty()) {
            return OsvMatchResult.NOT_COVERED;
        }

        VersionScheme scheme = VersionSchemes.forEcosystem(coordinate.ecosystem());

        // Keyed by CVE: one package can be hit by several advisories that alias the same CVE, and a
        // single alert per (component, CVE) is what the alert table stores.
        Map<String, CorrelationMatch> byCve = new LinkedHashMap<>();
        for (OsvAdvisory advisory : advisories) {
            evaluate(advisory, coordinate, scheme)
                    .ifPresent(match -> byCve.merge(match.cveId(), match, CorrelationMatch::best));
        }

        return new OsvMatchResult(true, List.copyOf(byCve.values()));
    }

    /**
     * What OSV says about the fix for one {@code (component, CVE)} pair.
     *
     * <p>Used by re-enrichment, which has an existing alert and needs to know whether OSV has
     * learned a fix version since the alert was raised. Empty when OSV does not cover the package,
     * does not match the version, or does not carry that CVE.
     */
    @Transactional(readOnly = true)
    public Optional<FixResolution> fixFor(ComponentCoordinate coordinate, String cveId) {
        if (cveId == null) {
            return Optional.empty();
        }
        return match(coordinate).matches().stream()
                .filter(m -> cveId.equalsIgnoreCase(m.cveId()))
                .map(CorrelationMatch::fix)
                .findFirst();
    }

    /* ------------------------------------------------------------------ */
    /* One advisory                                                       */
    /* ------------------------------------------------------------------ */

    private Optional<CorrelationMatch> evaluate(OsvAdvisory advisory, ComponentCoordinate coordinate,
                                                VersionScheme scheme) {
        if (!advisory.isCurrent()) {
            // Withdrawn: the record still exists so a reversal needs no re-import, but it must not
            // raise anything.
            return Optional.empty();
        }

        String cveId = advisory.cveAlias();
        if (cveId == null) {
            // The funnel is CVE-driven end to end: KEV, EPSS and the CVE browser are all keyed by
            // CVE id, and an alert with no CVE could never be enriched, sorted or explained. A
            // GHSA-only advisory is therefore skipped rather than stored half-connected. This is the
            // one known gap in OSV coverage and it is deliberate for Phase 2 — see PHASE2-CONTRACT.
            log.debug("OSV advisory {} for {} has no CVE alias; skipping", advisory.getOsvId(), advisory.getPackageName());
            return Optional.empty();
        }

        String version = coordinate.version();

        // An enumerated versions[] hit is the strongest evidence there is: the advisory names the
        // exact version the SBOM declares. Compared with the scheme rather than by string equality,
        // so an advisory listing "1.0" still matches an SBOM declaring "1.0.0".
        boolean exact = advisory.getVersions() != null && advisory.getVersions().stream()
                .anyMatch(listed -> scheme.contains(version, VersionRange.exact(listed)));

        List<OsvAffectedRange> matched = new ArrayList<>();
        for (OsvAffectedRange range : advisory.getRanges()) {
            if (!range.isEvaluable()) {
                continue;
            }
            if (scheme.contains(version, VersionRange.osv(range.getIntroduced(), range.getFixed(), range.getLastAffected()))) {
                matched.add(range);
            }
        }

        if (!exact && matched.isEmpty()) {
            return Optional.empty();
        }

        MatchConfidence confidence = exact ? MatchConfidence.EXACT : MatchConfidence.RANGE;
        return Optional.of(new CorrelationMatch(cveId, confidence, fixFrom(advisory, matched), advisory.getOsvId()));
    }

    /**
     * Derive the fix state from the ranges that actually matched.
     *
     * <ul>
     *   <li>Any matched range carrying a {@code fixed} event → {@code FIXED} at those versions. A
     *       component sitting in two matched ranges (a record with several affected branches) gets
     *       both fix versions, which is the honest answer: upgrade to whichever branch you are on.</li>
     *   <li>Every matched range open-ended — no {@code fixed}, no {@code last_affected} → {@code NO_FIX}.
     *       That is OSV positively stating no fixed release exists, not an absence of data.</li>
     *   <li>Otherwise {@code UNKNOWN}: a {@code last_affected} bound says where the exposure ends
     *       without naming the release that ended it.</li>
     * </ul>
     *
     * <p>When only the enumerated {@code versions[]} list matched there are no ranges to read, so any
     * {@code fixed} event anywhere on the advisory is used — the record has one affected package and
     * one fix.
     */
    private static FixResolution fixFrom(OsvAdvisory advisory, List<OsvAffectedRange> matched) {
        List<OsvAffectedRange> source = matched.isEmpty() ? advisory.getRanges() : matched;

        Set<String> fixedVersions = new LinkedHashSet<>();
        boolean allOpenEnded = !source.isEmpty();
        for (OsvAffectedRange range : source) {
            if (range.getFixed() != null && !range.getFixed().isBlank()) {
                fixedVersions.add(range.getFixed().trim());
            }
            if (range.getFixed() != null || range.getLastAffected() != null) {
                allOpenEnded = false;
            }
        }

        if (!fixedVersions.isEmpty()) {
            return FixResolution.fixed(fixedVersions, FixSource.OSV);
        }
        if (allOpenEnded && !matched.isEmpty()) {
            return FixResolution.noFix(FixSource.OSV);
        }
        return FixResolution.unknown(FixSource.OSV);
    }

}
