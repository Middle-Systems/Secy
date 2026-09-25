package net.jdesive.secy.model.component;

import net.jdesive.secy.correlation.ComponentCoordinate;
import net.jdesive.secy.correlation.Cpe23;
import net.jdesive.secy.correlation.version.VersionScheme;
import net.jdesive.secy.correlation.version.VersionSchemes;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.IdentityConflictType;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Pass A of M1c's identity checking (ROADMAP.md — "Canonical component identity"): does <em>one</em>
 * component instance's own declared secondary identifiers (CPE, SWID, content hash) agree with its
 * PURL-primary identity and with each other? Pure and Spring/JPA-free — {@code SBOMService} calls
 * this at ingest and persists the verdict; the cross-instance hash-collision pass (Pass B) is a
 * separate, DB-backed step in {@code ComponentIdentityService}.
 *
 * <p><b>This has nothing to do with {@code MatchConfidence}.</b> That is a per-{@code (component,
 * CVE)} alert value computed at correlation time; this is a per-component, CVE-independent judgment
 * computed once at ingestion from the document's own facts. See {@link IdentityConfidence}'s Javadoc
 * for the full orthogonality note.
 *
 * <h2>Why token overlap, not string equality</h2>
 *
 * <p>PURL and CPE naming conventions differ systematically — {@code cpe:2.3:a:apache:log4j:2.14.1:…}
 * versus {@code pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1} name the exact same artifact
 * with not one identical substring in vendor/product versus namespace/name. Exact-string comparison
 * would flag most real, correct CPEs as conflicts. Token overlap — do the two identities share at
 * least one meaningful word, case-insensitively — is the conservative test that lets
 * {@code apache}/{@code log4j} agree with {@code org.apache.logging.log4j}/{@code log4j-core}
 * without also agreeing with unrelated products that merely reuse common words (the stoplist exists
 * for exactly that: {@code org}, {@code com}, … are not identifying tokens).
 */
public final class ComponentIdentityAssessor {

    /** Tokens too generic to count as a naming signal on either side of a comparison. */
    private static final Set<String> STOPLIST = Set.of(
            "com", "org", "net", "io", "www", "github", "gitlab", "bitbucket");

    private ComponentIdentityAssessor() {
    }

    /** One detected disagreement — see {@code SBOMComponentIdentityConflict} for the persisted shape. */
    public record DetectedConflict(IdentityConflictType type, SecondaryIdentifierType identifierType,
                                   String identifierValue, String detail) {
    }

    /** The verdict for one component instance: an {@link IdentityConfidence} plus every conflict that produced it (empty when {@code CORROBORATED}/{@code UNCORROBORATED}). */
    public record IdentityAssessment(IdentityConfidence confidence, List<DetectedConflict> conflicts) {
    }

    /**
     * Assess one normalized component against its own declared CPE/SWID identifiers and content
     * hashes. Never throws: a malformed identifier degrades to "unassessable" rather than failing
     * the whole ingest.
     */
    public static IdentityAssessment assess(NormalizedComponent c) {
        ComponentCoordinate coord = ComponentCoordinate.of(c.purl(), c.name(), c.version());
        String effectiveVersion = coord.version();
        Set<String> nameTokens = new LinkedHashSet<>();
        nameTokens.addAll(tokens(coord.name()));
        nameTokens.addAll(tokens(coord.namespace()));
        nameTokens.addAll(tokens(c.name()));
        VersionScheme scheme = VersionSchemes.generic();
        String subject = c.purl() != null ? c.purl() : ("name:" + c.name());

        List<DetectedConflict> conflicts = new ArrayList<>();
        boolean agreement = false;

        for (NormalizedComponent.Identifier identifier : c.identifiers()) {
            if (identifier.type() == SecondaryIdentifierType.CPE) {
                Optional<Cpe23> parsed = Cpe23.parse(identifier.value());
                if (parsed.isEmpty()) {
                    // CPE 2.2 URI, or otherwise unparsable — stored, deliberately not assessed.
                    continue;
                }
                Cpe23 cpe = parsed.get();
                boolean productWildcard = Cpe23.ANY.equals(cpe.product());
                boolean vendorWildcard = Cpe23.ANY.equals(cpe.vendor());
                Set<String> productTokens = tokens(cpe.product());
                Set<String> vendorTokens = tokens(cpe.vendor());
                boolean productOverlap = !productWildcard && overlaps(productTokens, nameTokens);
                boolean vendorOverlap = !vendorWildcard && overlaps(vendorTokens, nameTokens);

                boolean nameMismatch = !nameTokens.isEmpty() && !productWildcard && !productOverlap
                        && (vendorWildcard || !vendorOverlap);
                if (nameMismatch) {
                    conflicts.add(new DetectedConflict(IdentityConflictType.CPE_NAME_MISMATCH,
                            SecondaryIdentifierType.CPE, identifier.value(),
                            "CPE product '" + cpe.product() + "' shares no name token with " + subject));
                }

                boolean versionMismatch = cpe.hasConcreteVersion() && effectiveVersion != null
                        && !scheme.sameVersion(effectiveVersion, cpe.version());
                if (versionMismatch) {
                    conflicts.add(new DetectedConflict(IdentityConflictType.CPE_VERSION_MISMATCH,
                            SecondaryIdentifierType.CPE, identifier.value(),
                            "CPE version '" + cpe.version() + "' disagrees with declared version '"
                                    + effectiveVersion + "' of " + subject));
                }

                if (!nameMismatch && !versionMismatch && (productOverlap || vendorOverlap)) {
                    agreement = true;
                }
            } else if (identifier.type() == SecondaryIdentifierType.SWID) {
                String declaredName = identifier.declaredName();
                String declaredVersion = identifier.declaredVersion();
                boolean nameOverlap = false;
                boolean nameMismatch = false;

                if (declaredName != null) {
                    Set<String> swidNameTokens = tokens(declaredName);
                    nameOverlap = overlaps(swidNameTokens, nameTokens);
                    nameMismatch = !nameTokens.isEmpty() && !nameOverlap;
                    if (nameMismatch) {
                        conflicts.add(new DetectedConflict(IdentityConflictType.SWID_NAME_MISMATCH,
                                SecondaryIdentifierType.SWID, identifier.value(),
                                "SWID name '" + declaredName + "' shares no name token with " + subject));
                    }
                }

                boolean versionMismatch = declaredVersion != null && effectiveVersion != null
                        && !scheme.sameVersion(effectiveVersion, declaredVersion);
                if (versionMismatch) {
                    conflicts.add(new DetectedConflict(IdentityConflictType.SWID_VERSION_MISMATCH,
                            SecondaryIdentifierType.SWID, identifier.value(),
                            "SWID version '" + declaredVersion + "' disagrees with declared version '"
                                    + effectiveVersion + "' of " + subject));
                }

                if (!nameMismatch && !versionMismatch && nameOverlap) {
                    agreement = true;
                }
            }
        }

        conflicts.addAll(hashConflicts(c));

        IdentityConfidence confidence = !conflicts.isEmpty() ? IdentityConfidence.CONFLICTING
                : agreement ? IdentityConfidence.CORROBORATED
                : IdentityConfidence.UNCORROBORATED;
        return new IdentityAssessment(confidence, conflicts);
    }

    /**
     * A digest never counts as agreement — a hash says nothing about a name — but two different
     * values for the same canonical algorithm on the same artifact is a contradiction in terms.
     */
    private static List<DetectedConflict> hashConflicts(NormalizedComponent c) {
        List<DetectedConflict> conflicts = new ArrayList<>();
        Map<String, String> firstValueByAlgorithm = new LinkedHashMap<>();
        Set<String> alreadyFlagged = new LinkedHashSet<>();
        for (NormalizedComponent.ComponentHashValue hash : c.hashes()) {
            String canonical = canonicalAlgorithm(hash.algorithm());
            if (canonical == null || hash.value() == null) {
                continue;
            }
            String existing = firstValueByAlgorithm.putIfAbsent(canonical, hash.value());
            if (existing != null && !existing.equals(hash.value()) && alreadyFlagged.add(canonical)) {
                conflicts.add(new DetectedConflict(IdentityConflictType.HASH_ALGORITHM_DISAGREEMENT,
                        SecondaryIdentifierType.HASH, canonical + ":" + hash.value(),
                        "Two declared " + canonical + " digests disagree: " + existing + " vs " + hash.value()));
            }
        }
        return conflicts;
    }

    private static String canonicalAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            return null;
        }
        return algorithm.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
    }

    private static boolean overlaps(Set<String> a, Set<String> b) {
        if (a.isEmpty() || b.isEmpty()) {
            return false;
        }
        for (String token : a) {
            if (b.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /** Lower-case, split on non-alphanumeric runs, drop short/stoplisted tokens. */
    private static Set<String> tokens(String s) {
        if (s == null || s.isBlank()) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String part : s.toLowerCase(Locale.ROOT).split("[^a-z0-9]+")) {
            if (part.length() >= 2 && !STOPLIST.contains(part)) {
                out.add(part);
            }
        }
        return out;
    }

}
