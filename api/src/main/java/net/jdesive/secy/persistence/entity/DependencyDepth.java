package net.jdesive.secy.persistence.entity;

/**
 * How far a component sits from a product's own direct dependency declarations (M1i, ROADMAP.md —
 * "Scoring engine rework"; computed since M1l, ROADMAP.md — "Dependency graph preserved").
 *
 * <p>Lives in {@code persistence.entity} — {@code sbom_component.dependency_depth} is {@code
 * @Enumerated(EnumType.STRING)} onto this enum (migration {@code 030}).
 *
 * <h2>Classification (M1l, {@code DependencyGraphAnalyzer})</h2>
 *
 * <p>A cycle-safe BFS over the document's directed dependency edges (CycloneDX {@code
 * dependencies[]}; SPDX {@code DEPENDS_ON} and the seven {@code *_DEPENDENCY_OF} types only)
 * classifies every component once at ingest:
 *
 * <ul>
 *   <li>{@link #DIRECT} — reachable from the product root in exactly one hop (wins even when a
 *       longer path also exists).</li>
 *   <li>{@link #TRANSITIVE} — reachable in two or more hops.</li>
 *   <li>{@link #UNKNOWN} — the component's {@code bomRef} is null, shared by two or more
 *       components (ambiguous), equal to a root ref, or simply unreachable from every root (no
 *       root at all counts as unreachable). "Unknown is not harmless": none of these invent a
 *       fallback identity or earn the {@link #TRANSITIVE} discount.</li>
 * </ul>
 *
 * <p>Asset/scanner-derived alerts ({@code AssetComponent}) have no dependency graph at all and stay
 * {@link #UNKNOWN} permanently — see ROADMAP.md's M1l decisions. A component built directly (test
 * fixtures, the golden correlation set) or ingested before M1l also reads as {@link #UNKNOWN},
 * because {@code RiskScoreInputs.dependencyDepthOf} treats a null column the same as an explicit
 * {@link #UNKNOWN} value.
 */
public enum DependencyDepth {

    /** Declared directly by the product's own manifest. */
    DIRECT,

    /** Pulled in transitively, through another dependency. */
    TRANSITIVE,

    /** Not tracked, or not classifiable — see this enum's classification table. */
    UNKNOWN

}
