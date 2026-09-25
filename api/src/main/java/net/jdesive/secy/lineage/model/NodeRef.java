package net.jdesive.secy.lineage.model;

import net.jdesive.secy.lineage.NodeLabel;

/**
 * A pointer to a graph node by its label and per-tenant-unique key, without carrying its
 * properties. Used to spell an edge's endpoints without duplicating the node's data.
 */
public record NodeRef(NodeLabel label, String key) {
}
