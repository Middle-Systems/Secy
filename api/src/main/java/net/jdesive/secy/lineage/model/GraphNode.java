package net.jdesive.secy.lineage.model;

import net.jdesive.secy.lineage.NodeLabel;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One vertex to write: a label, its per-tenant-unique key (matching some {@link NodeRef} that
 * points at it), and its properties.
 *
 * <p>{@link #properties()} is defensively copied into an unmodifiable {@link LinkedHashMap} so
 * iteration order — which {@link net.jdesive.secy.lineage.CypherRenderer} relies on for
 * deterministic output — always follows {@link NodeLabel#propertyKeys()} order, exactly as the
 * planner built it.
 */
public record GraphNode(NodeLabel label, String key, Map<String, Object> properties) {

    public GraphNode {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(properties, "properties");
        properties = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(properties));
    }

    public NodeRef ref() {
        return new NodeRef(label, key);
    }

}
