package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphEdge;
import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.lineage.model.NodeRef;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LineageGraphSnapshotTest {

    private static final UUID TENANT = UUID.randomUUID();

    @Test
    void acceptsAValidSnapshot() {
        GraphNode product = node(NodeLabel.PRODUCT, "p1", Map.of("tenant_id", TENANT.toString(), "pg_id", "p1",
                "unassigned", false));
        GraphNode sbom = node(NodeLabel.SBOM, "s1", Map.of("tenant_id", TENANT.toString(), "pg_id", "s1"));
        GraphEdge edge = new GraphEdge(EdgeType.HAS_SBOM, product.ref(), sbom.ref());

        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(product, sbom), List.of(edge));

        assertThat(snapshot.nodes()).hasSize(2);
        assertThat(snapshot.edges()).hasSize(1);
    }

    @Test
    void rejectsADanglingEdge() {
        GraphNode product = node(NodeLabel.PRODUCT, "p1", Map.of());
        NodeRef missingSbom = new NodeRef(NodeLabel.SBOM, "does-not-exist");
        GraphEdge edge = new GraphEdge(EdgeType.HAS_SBOM, product.ref(), missingSbom);

        assertThatThrownBy(() -> new LineageGraphSnapshot(TENANT, List.of(product), List.of(edge)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Dangling edge endpoint");
    }

    @Test
    void rejectsADisallowedLabelPair() {
        GraphNode product = node(NodeLabel.PRODUCT, "p1", Map.of());
        GraphNode component = node(NodeLabel.COMPONENT, "c1", Map.of());
        // HAS_SBOM only allows (PRODUCT, SBOM) -- not (PRODUCT, COMPONENT).
        GraphEdge edge = new GraphEdge(EdgeType.HAS_SBOM, product.ref(), component.ref());

        assertThatThrownBy(() -> new LineageGraphSnapshot(TENANT, List.of(product, component), List.of(edge)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not allow");
    }

    @Test
    void rejectsDuplicateNodeKeysWithinTheSameLabel() {
        GraphNode a = node(NodeLabel.PRODUCT, "dup", Map.of());
        GraphNode b = node(NodeLabel.PRODUCT, "dup", Map.of());

        assertThatThrownBy(() -> new LineageGraphSnapshot(TENANT, List.of(a, b), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate node");
    }

    @Test
    void rejectsAnUnknownPropertyKey() {
        GraphNode node = node(NodeLabel.PRODUCT, "p1", Map.of("not_a_real_key", "value"));

        assertThatThrownBy(() -> new LineageGraphSnapshot(TENANT, List.of(node), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown property key");
    }

    @Test
    void rejectsANonPrimitivePropertyValue() {
        GraphNode node = node(NodeLabel.PRODUCT, "p1", Map.of("name", List.of("not", "a", "primitive")));

        assertThatThrownBy(() -> new LineageGraphSnapshot(TENANT, List.of(node), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported property value type");
    }

    @Test
    void acceptsEveryDocumentedPrimitiveType() {
        Map<String, Object> props = new java.util.LinkedHashMap<>();
        props.put("tenant_id", TENANT.toString());
        props.put("pg_id", "p1");
        props.put("name", "a string");
        props.put("unassigned", true);
        GraphNode node = node(NodeLabel.PRODUCT, "p1", props);

        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(TENANT, List.of(node), List.of());
        assertThat(snapshot.nodes()).containsExactly(node);
    }

    private static GraphNode node(NodeLabel label, String key, Map<String, Object> properties) {
        return new GraphNode(label, key, properties);
    }

}
