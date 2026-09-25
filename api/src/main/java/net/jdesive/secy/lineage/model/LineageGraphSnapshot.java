package net.jdesive.secy.lineage.model;

import net.jdesive.secy.lineage.EdgeType;
import net.jdesive.secy.lineage.NodeLabel;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * The complete lineage graph for one tenant, at one point in time: every node and edge {@link
 * net.jdesive.secy.lineage.LineagePlanner#plan} decided should exist.
 *
 * <p>Immutable and self-validating — a snapshot that fails these invariants can never be
 * constructed, so {@link net.jdesive.secy.lineage.CypherRenderer} and every writer can trust it
 * unconditionally rather than re-checking it.
 *
 * <h2>Invariants enforced here</h2>
 * <ul>
 *   <li>No two nodes share a {@code (label, key)} pair.</li>
 *   <li>Every edge's {@code from}/{@code to} resolves to a node actually in {@link #nodes()}.</li>
 *   <li>Every edge's {@code (fromLabel, toLabel)} pair is one its {@link EdgeType} allows.</li>
 *   <li>Every node's property keys are a subset of its label's {@link NodeLabel#propertyKeys()}.</li>
 *   <li>Every property value is a {@code String}, {@code Long}, {@code Integer}, {@code Double} or
 *       {@code Boolean} — the only types {@link net.jdesive.secy.lineage.AgeSql} /
 *       {@link net.jdesive.secy.lineage.CypherRenderer} know how to serialize as agtype.</li>
 * </ul>
 */
public record LineageGraphSnapshot(UUID tenantId, List<GraphNode> nodes, List<GraphEdge> edges) {

    public LineageGraphSnapshot {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(nodes, "nodes");
        Objects.requireNonNull(edges, "edges");
        nodes = List.copyOf(nodes);
        edges = List.copyOf(edges);

        Set<NodeRef> seen = new HashSet<>();
        Map<NodeRef, NodeLabel> refToLabel = new HashMap<>();
        for (GraphNode node : nodes) {
            NodeRef ref = node.ref();
            if (!seen.add(ref)) {
                throw new IllegalArgumentException("Duplicate node (label,key): " + ref);
            }
            refToLabel.put(ref, node.label());

            Set<String> allowedKeys = new HashSet<>(node.label().propertyKeys());
            for (String key : node.properties().keySet()) {
                if (!allowedKeys.contains(key)) {
                    throw new IllegalArgumentException(
                            "Unknown property key '" + key + "' for label " + node.label().label());
                }
            }
            for (Object value : node.properties().values()) {
                if (value != null && !isPrimitiveValue(value)) {
                    throw new IllegalArgumentException(
                            "Unsupported property value type: " + value.getClass());
                }
            }
        }

        for (GraphEdge edge : edges) {
            NodeLabel fromLabel = refToLabel.get(edge.from());
            NodeLabel toLabel = refToLabel.get(edge.to());
            if (fromLabel == null) {
                throw new IllegalArgumentException("Dangling edge endpoint: " + edge.from());
            }
            if (toLabel == null) {
                throw new IllegalArgumentException("Dangling edge endpoint: " + edge.to());
            }
            if (!edge.type().allows(fromLabel, toLabel)) {
                throw new IllegalArgumentException("Edge type " + edge.type().label()
                        + " does not allow (" + fromLabel.label() + " -> " + toLabel.label() + ")");
            }
        }
    }

    private static boolean isPrimitiveValue(Object value) {
        return value instanceof String
                || value instanceof Long
                || value instanceof Integer
                || value instanceof Double
                || value instanceof Boolean;
    }

}
