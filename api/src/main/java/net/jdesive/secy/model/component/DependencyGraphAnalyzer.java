package net.jdesive.secy.model.component;

import net.jdesive.secy.persistence.entity.DependencyDepth;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Cycle-safe BFS classification of every ref in a document's dependency graph into DIRECT /
 * TRANSITIVE / UNKNOWN, with a hop distance and one representative shortest path (M1l,
 * ROADMAP.md — "Dependency graph preserved"). Pure and Spring/JPA-free, same pattern as {@link
 * ComponentIdentityAssessor}; {@code SBOMService} calls this once per document at ingest.
 *
 * <h2>Why BFS over refs, not components</h2>
 *
 * <p>The graph is built from every {@link DependencyEdge}'s raw refs — nested {@code
 * components[].components[]}, external-document refs, and non-package SPDX elements all
 * participate in distance/path even when they have no corresponding {@link NormalizedComponent}
 * row. Walking components instead would silently shorten or break paths that pass through a
 * ref with no component.
 *
 * <h2>Classification table</h2>
 *
 * <table border="1">
 *   <caption>Depth classification</caption>
 *   <tr><th>Condition</th><th>Result</th></tr>
 *   <tr><td>{@code bomRef == null}</td><td>UNKNOWN — no node identity possible</td></tr>
 *   <tr><td>bomRef shared by 2+ components</td><td>UNKNOWN — ambiguous/malformed document</td></tr>
 *   <tr><td>bomRef is one of the root refs</td><td>UNKNOWN — it is the product itself</td></tr>
 *   <tr><td>no root refs, or unreachable from every root</td><td>UNKNOWN — an incomplete graph must
 *       not earn the TRANSITIVE discount</td></tr>
 *   <tr><td>{@code dist == 1}</td><td>DIRECT (wins even if a longer path also exists)</td></tr>
 *   <tr><td>{@code dist >= 2}</td><td>TRANSITIVE, distance = dist</td></tr>
 * </table>
 */
public final class DependencyGraphAnalyzer {

    /** Beyond this many hops, {@link Position#path()} is dropped (null) but depth/distance stay exact. */
    public static final int MAX_PATH_HOPS = 32;

    public static final Position UNKNOWN = new Position(DependencyDepth.UNKNOWN, null, null);

    private DependencyGraphAnalyzer() {
    }

    /** One component's classification. {@code path} may be null — see {@link #MAX_PATH_HOPS}. */
    public record Position(DependencyDepth depth, Integer distance, List<String> path) {
    }

    /** The BFS result for a whole document: every classified ref's {@link Position}. */
    public static final class Analysis {
        private final Map<String, Position> byRef;

        private Analysis(Map<String, Position> byRef) {
            this.byRef = byRef;
        }

        /** The position for {@code bomRef} — {@link #UNKNOWN} when {@code bomRef} is null or not reachable. */
        public Position positionOf(String bomRef) {
            if (bomRef == null) {
                return UNKNOWN;
            }
            return byRef.getOrDefault(bomRef, UNKNOWN);
        }
    }

    public static Analysis analyze(Set<String> rootRefs, List<DependencyEdge> edges, List<NormalizedComponent> components) {
        // Ambiguous/duplicate bom-refs across components -> UNKNOWN regardless of reachability.
        Map<String, Integer> refCounts = new HashMap<>();
        for (NormalizedComponent c : components) {
            if (c.bomRef() != null) {
                refCounts.merge(c.bomRef(), 1, Integer::sum);
            }
        }
        Set<String> ambiguousRefs = new HashSet<>();
        for (Map.Entry<String, Integer> entry : refCounts.entrySet()) {
            if (entry.getValue() > 1) {
                ambiguousRefs.add(entry.getKey());
            }
        }

        Set<String> roots = rootRefs == null ? Set.of() : rootRefs;

        // Adjacency, document order preserved.
        Map<String, LinkedHashSet<String>> adjacency = new LinkedHashMap<>();
        if (edges != null) {
            for (DependencyEdge edge : edges) {
                adjacency.computeIfAbsent(edge.fromRef(), k -> new LinkedHashSet<>()).add(edge.toRef());
            }
        }

        Map<String, Integer> dist = new HashMap<>();
        Map<String, String> parent = new HashMap<>();

        if (!roots.isEmpty()) {
            // Deterministic seeding order -- NormalizedSbom.dependencyRootRefs is a Set.copyOf with
            // no guaranteed iteration order.
            List<String> sortedRoots = new ArrayList<>(new TreeSet<>(roots));
            Deque<String> queue = new ArrayDeque<>();
            for (String root : sortedRoots) {
                if (!dist.containsKey(root)) {
                    dist.put(root, 0);
                    queue.add(root);
                }
            }
            while (!queue.isEmpty()) {
                String node = queue.poll();
                int d = dist.get(node);
                for (String child : adjacency.getOrDefault(node, new LinkedHashSet<>())) {
                    if (!dist.containsKey(child)) {
                        dist.put(child, d + 1);
                        parent.put(child, node);
                        queue.add(child);
                    }
                }
            }
        }

        Map<String, Position> byRef = new HashMap<>();
        for (NormalizedComponent c : components) {
            String ref = c.bomRef();
            if (ref == null) {
                continue; // never looked up -- positionOf(null) returns UNKNOWN directly
            }
            if (ambiguousRefs.contains(ref) || roots.contains(ref)) {
                byRef.put(ref, UNKNOWN);
                continue;
            }
            Integer d = dist.get(ref);
            if (d == null || d == 0) {
                // d == 0 only happens for a ref that is itself a root -- already excluded above, so
                // this branch is "unreachable" in practice, kept for defensiveness.
                byRef.put(ref, UNKNOWN);
                continue;
            }
            DependencyDepth depth = d == 1 ? DependencyDepth.DIRECT : DependencyDepth.TRANSITIVE;
            List<String> path = d > MAX_PATH_HOPS ? null : buildPath(ref, parent);
            byRef.put(ref, new Position(depth, d, path));
        }

        return new Analysis(byRef);
    }

    private static List<String> buildPath(String ref, Map<String, String> parent) {
        List<String> reversed = new ArrayList<>();
        String current = ref;
        while (current != null) {
            reversed.add(current);
            current = parent.get(current);
        }
        Collections.reverse(reversed);
        return List.copyOf(reversed);
    }

}
