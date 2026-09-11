package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.version.VersionRange;
import net.jdesive.secy.correlation.version.VersionScheme;
import net.jdesive.secy.correlation.version.VersionSchemes;
import net.jdesive.secy.persistence.CPEMatchRepository;
import net.jdesive.secy.persistence.entity.CPEMatch;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The fallback correlation path: NVD CPE matching for what OSV does not cover.
 *
 * <p>Reached for two kinds of thing — open-source packages OSV has no advisories for, and (from
 * Phase 4) OS packages, firmware and proprietary products that were never in a package ecosystem.
 * NVD stays canonical for the second group; for the first it is a best effort, and the confidence
 * on every alert says so.
 *
 * <h2>What replaced {@code criteria.split(":")[5]}</h2>
 *
 * <p>The old code read the sixth colon-delimited field of the criteria string as "the vulnerable
 * version" and reported anything at or below it. Three things were wrong with that, and each is
 * fixed here:
 *
 * <ol>
 *   <li>On modern NVD rows that field is {@code *}, because the real range lives in the four
 *       {@code versionStart*}/{@code versionEnd*} attributes — which the schema did not have. Read
 *       literally, {@code *} matched every version of every component. Those columns exist now and
 *       are evaluated as a {@link VersionRange}.</li>
 *   <li>The comparison was "component version ≤ CPE version", so every version below the affected
 *       one was reported too. A range has a lower bound and it is honoured.</li>
 *   <li>The criteria string was split naively, so an escaped colon inside a field shifted every
 *       later field. {@link Cpe23} splits on unescaped colons only.</li>
 * </ol>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CpeMatcher {

    private final CPEMatchRepository cpeMatchRepository;

    /**
     * Evaluate a component against the NVD CPE corpus.
     *
     * <p>The version comparison uses {@link VersionSchemes#generic()} unconditionally: a CPE row
     * carries no ecosystem, and the corpus mixes OpenSSL patch letters, Java update strings and
     * dotted integers with no convention that would let a stricter scheme apply.
     */
    @Transactional(readOnly = true)
    public List<CorrelationMatch> match(ComponentCoordinate coordinate) {
        List<PurlCpeBridge.CpeCandidate> candidates = PurlCpeBridge.candidatesFor(coordinate);
        if (candidates.isEmpty()) {
            return List.of();
        }

        VersionScheme scheme = VersionSchemes.generic();
        Map<String, CorrelationMatch> byCve = new LinkedHashMap<>();

        for (PurlCpeBridge.CpeCandidate candidate : candidates) {
            for (CPEMatch row : cpeMatchRepository.findVulnerableByCriteriaLike(candidate.criteriaPattern())) {
                evaluate(row, candidate, coordinate, scheme)
                        .ifPresent(match -> byCve.merge(match.cveId(), match, CorrelationMatch::best));
            }
        }

        return List.copyOf(byCve.values());
    }

    /* ------------------------------------------------------------------ */
    /* One cpe_match row                                                  */
    /* ------------------------------------------------------------------ */

    private Optional<CorrelationMatch> evaluate(CPEMatch row, PurlCpeBridge.CpeCandidate candidate,
                                                ComponentCoordinate coordinate, VersionScheme scheme) {
        Optional<Cpe23> parsed = Cpe23.parse(row.getCriteria());
        if (parsed.isEmpty()) {
            log.debug("Unparseable CPE criteria on cpe_match {}: {}", row.getId(), row.getCriteria());
            return Optional.empty();
        }
        Cpe23 cpe = parsed.get();

        // The LIKE query is a coarse pre-filter — an unescaped underscore in a package name widens
        // it, and a wildcard vendor widens it a lot. Identity is decided here.
        if (!cpe.productMatches(candidate.product())) {
            return Optional.empty();
        }
        if (candidate.vendor() != null && !cpe.vendorMatches(candidate.vendor())) {
            return Optional.empty();
        }

        Vulnerability cve = row.getOperator() == null ? null : row.getOperator().getCve();
        if (cve == null || cve.getId() == null) {
            return Optional.empty();
        }

        Verdict verdict = versionVerdict(row, cpe, coordinate.version(), scheme);
        if (verdict == null) {
            return Optional.empty();
        }

        // A candidate can never claim more than its ceiling: a product-only name guess stays
        // HEURISTIC however neatly the version range fits.
        MatchConfidence confidence = weaker(candidate.ceiling(), verdict.confidence());
        return Optional.of(new CorrelationMatch(cve.getId(), confidence, verdict.fix(), row.getCriteria()));
    }

    private record Verdict(MatchConfidence confidence, FixResolution fix) {
    }

    /**
     * Decide whether the component's version falls in this row's affected versions, and what the row
     * implies about a fix.
     *
     * @return null when the row does not cover this version
     */
    private static Verdict versionVerdict(CPEMatch row, Cpe23 cpe, String version, VersionScheme scheme) {
        if (row.hasVersionRange()) {
            boolean inRange = scheme.contains(version, VersionRange.cpe(
                    row.getVersionStartIncluding(), row.getVersionStartExcluding(),
                    row.getVersionEndIncluding(), row.getVersionEndExcluding()));
            if (!inRange) {
                return null;
            }
            return new Verdict(MatchConfidence.RANGE, cpeRangeFix(row));
        }

        if (cpe.hasConcreteVersion()) {
            // A row naming one version. Compared with the scheme rather than by string equality so
            // "1.0" in NVD still matches "1.0.0" in the SBOM. Still RANGE, not EXACT: EXACT is
            // reserved for an advisory that identified the package itself, which CPE never does.
            if (version == null || !scheme.sameVersion(version, cpe.version())) {
                return null;
            }
            return new Verdict(MatchConfidence.RANGE, FixResolution.unknown(FixSource.CPE_RANGE));
        }

        // Wildcard version, no range attributes: NVD is saying every version of this product is
        // affected. Sometimes true (an unmaintained product), often a row NVD has not analysed yet,
        // and always the shape that produced the old code's false positives — so it reports, and it
        // reports as a guess.
        return new Verdict(MatchConfidence.HEURISTIC, FixResolution.unknown(FixSource.CPE_RANGE));
    }

    /**
     * The approximate fix version.
     *
     * <p>{@code versionEndExcluding} is the first version NVD says is <em>not</em> affected, which is
     * the fix — but only for the branch this row describes, and NVD writes one row per branch. It is
     * an inference from a range boundary rather than a vendor statement, which is exactly what
     * {@link FixSource#CPE_RANGE} means and how the UI flags it. {@code versionEndIncluding} is
     * deliberately not used: "affected up to and including 2.4" does not name the release that fixed
     * it.
     */
    private static FixResolution cpeRangeFix(CPEMatch row) {
        String end = row.getVersionEndExcluding();
        if (end != null && !end.isBlank()) {
            return FixResolution.fixed(end, FixSource.CPE_RANGE);
        }
        return FixResolution.unknown(FixSource.CPE_RANGE);
    }

    /** The lower of two confidences, using the enum's strongest-first declaration order. */
    private static MatchConfidence weaker(MatchConfidence a, MatchConfidence b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

}
