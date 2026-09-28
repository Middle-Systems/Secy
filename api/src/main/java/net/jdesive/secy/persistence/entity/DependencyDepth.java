package net.jdesive.secy.persistence.entity;

/**
 * How far a component sits from a product's own direct dependency declarations (M1i,
 * ROADMAP.md — "Scoring engine rework").
 *
 * <p>Lives in {@code persistence.entity}, not {@code service.scoring}, even though nothing
 * persists it yet: M1l (the dependency-graph milestone) is expected to add a real column backed by
 * this enum, and putting it here now means that later change is additive — {@code @Enumerated} onto
 * a new {@code sbom_component} column — rather than a package move that would touch every file that
 * imports it.
 *
 * <p><b>M1i cannot compute this.</b> Neither {@code SBOMComponent} nor {@code NormalizedComponent}
 * carries a depth/direct-transitive/path field, {@code SpdxNormalizer}'s own Javadoc says the
 * relationship graph is not traversed, and M1h's {@code dependencyRelationshipRefs} is a flat
 * presence-only set with edge direction already lost by the time correlation sees it. So every
 * {@code RiskScoreInputs.from(VulnerabilityAlert)} hard-codes {@link #UNKNOWN} today — a declared,
 * neutral placeholder (weight {@code 1.0}, same as {@link #DIRECT}) that M1l plugs a real value into
 * later without changing the scoring formula's shape.
 */
public enum DependencyDepth {

    /** Declared directly by the product's own manifest. */
    DIRECT,

    /** Pulled in transitively, through another dependency. */
    TRANSITIVE,

    /** Not tracked — every component today, until M1l. */
    UNKNOWN

}
