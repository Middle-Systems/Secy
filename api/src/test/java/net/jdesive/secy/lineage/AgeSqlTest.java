package net.jdesive.secy.lineage;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AgeSqlTest {

    @Test
    void wrapProducesTheExactExpectedString() {
        String wrapped = AgeSql.wrap("MATCH (n) RETURN n");

        assertThat(wrapped).isEqualTo(
                "SELECT * FROM ag_catalog.cypher('secy_lineage', $$ MATCH (n) RETURN n $$, ?) AS (v ag_catalog.agtype)");
    }

    @Test
    void ensureSchemaBlockCreatesTheGraph() {
        assertThat(AgeSql.ensureSchemaBlock()).contains("create_graph('secy_lineage')");
    }

    @Test
    void ensureSchemaBlockCreatesAVlabelAndGinIndexForEveryNodeLabel() {
        String block = AgeSql.ensureSchemaBlock();
        for (NodeLabel label : NodeLabel.values()) {
            assertThat(block).contains("create_vlabel('secy_lineage', '" + label.label() + "')");
            assertThat(block).contains("using gin (properties)");
        }
    }

    @Test
    void ensureSchemaBlockCreatesAnElabelAndStartEndIndexesForEveryEdgeType() {
        String block = AgeSql.ensureSchemaBlock();
        for (EdgeType type : EdgeType.values()) {
            assertThat(block).contains("create_elabel('secy_lineage', '" + type.label() + "')");
            assertThat(block).contains("(start_id)");
            assertThat(block).contains("(end_id)");
        }
    }

    @Test
    void ensureSchemaBlockStartsAndEndsWithADoBlock() {
        String block = AgeSql.ensureSchemaBlock();
        assertThat(block).startsWith("do $$");
        assertThat(block).endsWith("end $$;");
    }

}
