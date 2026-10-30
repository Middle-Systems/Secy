package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphEdge;
import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.lineage.model.NodeRef;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CypherRendererTest {

    private final CypherRenderer renderer = new CypherRenderer();

    private static final UUID TENANT = UUID.randomUUID();

    @Test
    void deleteIsAlwaysFirstEvenForAnEmptySnapshot() {
        LineageGraphSnapshot empty = new LineageGraphSnapshot(TENANT, List.of(), List.of());
        List<CypherStatement> statements = renderer.renderReplace(empty, 500);

        assertThat(statements).hasSize(1);
        assertThat(statements.get(0).cypher()).isEqualTo("MATCH (n {tenant_id: $tenant_id}) DETACH DELETE n");
        assertThat(statements.get(0).params()).containsExactly(Map.entry("tenant_id", TENANT.toString()));
    }

    @Test
    void exactNodeStatementText() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("tenant_id", TENANT.toString());
        props.put("pg_id", "p1");
        props.put("name", "Widget");
        GraphNode product = new GraphNode(NodeLabel.PRODUCT, "p1", props);

        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(product), List.of());
        List<CypherStatement> statements = renderer.renderReplace(snapshot, 500);

        assertThat(statements).hasSize(2); // delete + one node statement
        CypherStatement nodeStatement = statements.get(1);
        assertThat(nodeStatement.cypher()).isEqualTo("UNWIND $rows AS row CREATE (:Product {tenant_id: row.tenant_id, "
                + "pg_id: row.pg_id, name: row.name, tag_value: row.tag_value, unassigned: row.unassigned, "
                + "created_at: row.created_at})");
        assertThat(nodeStatement.params()).containsOnlyKeys("rows");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) nodeStatement.params().get("rows");
        assertThat(rows).containsExactly(props);
    }

    @Test
    void exactEdgeStatementText() {
        GraphNode product = new GraphNode(NodeLabel.PRODUCT, "p1", Map.of());
        GraphNode sbom = new GraphNode(NodeLabel.SBOM, "s1", Map.of());
        GraphEdge edge = new GraphEdge(EdgeType.HAS_SBOM, product.ref(), sbom.ref());

        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(product, sbom), List.of(edge));
        List<CypherStatement> statements = renderer.renderReplace(snapshot, 500);

        CypherStatement edgeStatement = statements.get(statements.size() - 1);
        assertThat(edgeStatement.cypher()).isEqualTo(
                "UNWIND $rows AS row MATCH (a:Product {tenant_id: row.tenant_id, pg_id: row.from}), "
                        + "(b:SBOM {tenant_id: row.tenant_id, pg_id: row.to}) "
                        + "CREATE (a)-[:HAS_SBOM {tenant_id: row.tenant_id}]->(b)");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) edgeStatement.params().get("rows");
        assertThat(rows).containsExactly(Map.of("tenant_id", TENANT.toString(), "from", "p1", "to", "s1"));
    }

    @Test
    void chunksNodesByBatchSize() {
        List<GraphNode> nodes = List.of(
                new GraphNode(NodeLabel.PRODUCT, "p1", Map.of()),
                new GraphNode(NodeLabel.PRODUCT, "p2", Map.of()),
                new GraphNode(NodeLabel.PRODUCT, "p3", Map.of()));
        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, nodes, List.of());

        List<CypherStatement> statements = renderer.renderReplace(snapshot, 2);

        // delete + 2 node-batches (2 rows, then 1 row)
        assertThat(statements).hasSize(3);
        assertThat(rowCount(statements.get(1))).isEqualTo(2);
        assertThat(rowCount(statements.get(2))).isEqualTo(1);
    }

    @Test
    void nodesAreGroupedByLabelInOrdinalOrder() {
        GraphNode component = new GraphNode(NodeLabel.COMPONENT, "c1", Map.of());
        GraphNode sbom = new GraphNode(NodeLabel.SBOM, "s1", Map.of());
        GraphNode product = new GraphNode(NodeLabel.PRODUCT, "p1", Map.of());
        GraphEdge sbomContainsComponent = new GraphEdge(EdgeType.CONTAINS, sbom.ref(), component.ref());

        // Snapshot requires component's SBOM to exist -- build with all three in a non-ordinal order.
        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(component, sbom, product),
                List.of(sbomContainsComponent));
        List<CypherStatement> statements = renderer.renderReplace(snapshot, 500);

        // delete, then PRODUCT (ordinal 0), then SBOM (ordinal 1), then COMPONENT (ordinal 2), then the edge.
        assertThat(statements.get(1).cypher()).contains(":Product ");
        assertThat(statements.get(2).cypher()).contains(":SBOM ");
        assertThat(statements.get(3).cypher()).contains(":Component ");
    }

    @Test
    void noStatementContainsDollarDollarQuestionMarkOrLiteralData() {
        Map<String, Object> props = Map.of("tenant_id", TENANT.toString(), "pg_id", "p1", "name", "SECRET-LOOKING-VALUE");
        GraphNode product = new GraphNode(NodeLabel.PRODUCT, "p1", props);
        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(product), List.of());

        List<CypherStatement> statements = renderer.renderReplace(snapshot, 500);

        for (CypherStatement statement : statements) {
            assertThat(statement.cypher()).doesNotContain("$$");
            assertThat(statement.cypher()).doesNotContain("?");
            assertThat(statement.cypher()).doesNotContain("SECRET-LOOKING-VALUE");
            assertThat(statement.cypher()).doesNotContain(TENANT.toString());
        }
    }

    private static int rowCount(CypherStatement statement) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) statement.params().get("rows");
        return rows.size();
    }

}
