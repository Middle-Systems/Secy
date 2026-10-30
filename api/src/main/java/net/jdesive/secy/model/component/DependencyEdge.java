package net.jdesive.secy.model.component;

/**
 * One directed, document-declared dependency edge: {@code fromRef} depends on {@code toRef} —
 * CycloneDX {@code dependencies[].ref} → each of its {@code dependsOn[]}, or an SPDX relationship
 * resolved through {@code SpdxNormalizer}'s direction table (M1l, ROADMAP.md — "Dependency graph
 * preserved"). Both ends are format-native bom-refs/SPDXIDs — the same provenance-only handles
 * {@link NormalizedComponent#bomRef()} carries, not a stable identity.
 */
public record DependencyEdge(String fromRef, String toRef) {
}
