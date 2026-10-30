package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphEdge;
import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Renders a {@link LineageGraphSnapshot} into the ordered list of Cypher statements that replace
 * one tenant's subgraph, with all data carried as bind parameters — never interpolated into the
 * Cypher text itself (ROADMAP.md, M1d).
 *
 * <p>Order is always: one tenant-wide delete, then nodes (grouped by {@link NodeLabel}, ordinal
 * order), then edges (grouped by {@code (EdgeType, fromLabel, toLabel)}, in the snapshot's already
 * sorted order) — each group chunked to at most {@code batchSize} rows per {@code UNWIND}. The
 * delete being unconditionally first, even for an empty snapshot, is what makes a rebuild a true
 * replace regardless of what the graph held before (see {@code LineageRebuildService}'s Javadoc on
 * P2, the replace-semantics rebuildability property).
 */
public class CypherRenderer {

    public List<CypherStatement> renderReplace(LineageGraphSnapshot snapshot, int batchSize) {
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be positive: " + batchSize);
        }
        String tenantIdStr = snapshot.tenantId().toString();

        List<CypherStatement> statements = new ArrayList<>();
        statements.add(renderDelete(tenantIdStr));
        statements.addAll(renderNodes(snapshot.nodes(), batchSize));
        statements.addAll(renderEdges(snapshot.edges(), tenantIdStr, batchSize));
        return statements;
    }

    private CypherStatement renderDelete(String tenantIdStr) {
        return new CypherStatement(
                "MATCH (n {tenant_id: $tenant_id}) DETACH DELETE n",
                Map.of("tenant_id", tenantIdStr));
    }

    private List<CypherStatement> renderNodes(List<GraphNode> nodes, int batchSize) {
        List<CypherStatement> statements = new ArrayList<>();
        // Sort (stably -- ties keep the snapshot's own relative order) by label ordinal so
        // statements always come out in NodeLabel declaration order, regardless of what order the
        // snapshot's own node list happens to be in.
        List<GraphNode> ordered = nodes.stream()
                .sorted(java.util.Comparator.comparingInt(n -> n.label().ordinal()))
                .toList();
        Map<NodeLabel, List<GraphNode>> byLabel = new LinkedHashMap<>();
        for (GraphNode node : ordered) {
            byLabel.computeIfAbsent(node.label(), l -> new ArrayList<>()).add(node);
        }
        for (Map.Entry<NodeLabel, List<GraphNode>> entry : byLabel.entrySet()) {
            NodeLabel label = entry.getKey();
            String cypher = "UNWIND $rows AS row CREATE (:" + label.label() + " {" + propertyAssignments(label) + "})";
            for (List<GraphNode> chunk : chunk(entry.getValue(), batchSize)) {
                List<Map<String, Object>> rows = chunk.stream().map(GraphNode::properties).collect(Collectors.toList());
                statements.add(new CypherStatement(cypher, Map.of("rows", rows)));
            }
        }
        return statements;
    }

    private List<CypherStatement> renderEdges(List<GraphEdge> edges, String tenantIdStr, int batchSize) {
        List<CypherStatement> statements = new ArrayList<>();
        // Same stable-sort-then-group approach as renderNodes, keyed on (type, fromLabel, toLabel)
        // ordinal order, so grouping/order never depends on the snapshot's own edge list order.
        List<GraphEdge> ordered = edges.stream()
                .sorted(java.util.Comparator.<GraphEdge>comparingInt(e -> e.type().ordinal())
                        .thenComparingInt(e -> e.from().label().ordinal())
                        .thenComparingInt(e -> e.to().label().ordinal()))
                .toList();
        Map<GroupKey, List<GraphEdge>> byGroup = new LinkedHashMap<>();
        for (GraphEdge edge : ordered) {
            GroupKey key = new GroupKey(edge.type(), edge.from().label(), edge.to().label());
            byGroup.computeIfAbsent(key, k -> new ArrayList<>()).add(edge);
        }
        for (Map.Entry<GroupKey, List<GraphEdge>> entry : byGroup.entrySet()) {
            GroupKey key = entry.getKey();
            String cypher = "UNWIND $rows AS row MATCH (a:" + key.from().label()
                    + " {tenant_id: row.tenant_id, pg_id: row.from}), (b:" + key.to().label()
                    + " {tenant_id: row.tenant_id, pg_id: row.to}) CREATE (a)-[:" + key.type().label()
                    + " {tenant_id: row.tenant_id}]->(b)";
            for (List<GraphEdge> chunk : chunk(entry.getValue(), batchSize)) {
                List<Map<String, Object>> rows = new ArrayList<>();
                for (GraphEdge edge : chunk) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("tenant_id", tenantIdStr);
                    row.put("from", edge.from().key());
                    row.put("to", edge.to().key());
                    rows.add(row);
                }
                statements.add(new CypherStatement(cypher, Map.of("rows", rows)));
            }
        }
        return statements;
    }

    private static String propertyAssignments(NodeLabel label) {
        return label.propertyKeys().stream()
                .map(k -> k + ": row." + k)
                .collect(Collectors.joining(", "));
    }

    private static <T> List<List<T>> chunk(List<T> items, int batchSize) {
        List<List<T>> chunks = new ArrayList<>();
        for (int i = 0; i < items.size(); i += batchSize) {
            chunks.add(items.subList(i, Math.min(i + batchSize, items.size())));
        }
        return chunks;
    }

    private record GroupKey(EdgeType type, NodeLabel from, NodeLabel to) {
    }

}
