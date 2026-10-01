package net.jdesive.secy.model.component;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Accumulates {@link DependencyEdge}s while a normalizer walks a document's dependency structure
 * (M1l, ROADMAP.md — "Dependency graph preserved"). Both {@link CycloneDXNormalizer} and {@code
 * SpdxNormalizer} build one of these and call {@link #edges()} once at the end.
 *
 * <h2>Overflow is all-or-nothing</h2>
 *
 * <p>A document declaring more than {@link #MAX_EDGES} edges — pathological, but not impossible —
 * discards the <em>whole</em> graph rather than truncating it: a truncated graph could silently keep
 * a long transitive path to some component while dropping the direct {@code root -> X} edge that
 * would have classified it correctly, mislabeling a direct dependency as transitive. Losing the
 * entire graph (every component falls back to {@link net.jdesive.secy.persistence.entity.DependencyDepth#UNKNOWN})
 * is the safer failure mode — see that enum's classification table.
 */
public final class DependencyEdgeCollector {

    /** Package-private so {@code DependencyGraphParsingTest}/overflow tests can see it without reflection. */
    static final int MAX_EDGES = 250_000;

    private final int maxEdges;
    private final Set<DependencyEdge> edges = new LinkedHashSet<>();
    private boolean overflowed = false;

    public DependencyEdgeCollector() {
        this(MAX_EDGES);
    }

    /** Test-only: a small cap so overflow behaviour can be exercised without building 250k edges. */
    DependencyEdgeCollector(int maxEdges) {
        this.maxEdges = maxEdges;
    }

    /** Adds {@code from -> to}, trimmed; ignores null/blank either side and drops a self-loop. No-op once overflowed. */
    public void add(String from, String to) {
        if (overflowed) {
            return;
        }
        String f = trimToNull(from);
        String t = trimToNull(to);
        if (f == null || t == null || f.equals(t)) {
            return;
        }
        if (edges.size() >= maxEdges) {
            overflowed = true;
            edges.clear();
            return;
        }
        edges.add(new DependencyEdge(f, t));
    }

    /** Every edge added, document order, deduplicated — empty (not partial) when {@link #overflowed()}. */
    public List<DependencyEdge> edges() {
        return overflowed ? List.of() : List.copyOf(edges);
    }

    /** True once more than {@link #MAX_EDGES} distinct edges were offered — {@link #edges()} is empty from then on. */
    public boolean overflowed() {
        return overflowed;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

}
