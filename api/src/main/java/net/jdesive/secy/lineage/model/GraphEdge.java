package net.jdesive.secy.lineage.model;

import net.jdesive.secy.lineage.EdgeType;

import java.util.Objects;

/** One edge to write: its type and the two nodes it connects. */
public record GraphEdge(EdgeType type, NodeRef from, NodeRef to) {

    public GraphEdge {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
    }

}
