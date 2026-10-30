package net.jdesive.secy.lineage;

import java.util.Locale;

/**
 * Pure string-building for the two pieces of plain SQL {@link AgeLineageGraphWriter} sends: the
 * {@code ag_catalog.cypher(...)} wrapper every Cypher statement rides inside, and the one-time
 * schema-creation block that makes sure the graph, its vertex/edge labels and their indexes exist
 * before a rebuild writes to them.
 *
 * <p><b>Why no AGE JDBC driver.</b> Apache AGE's own JDBC driver is not published to Maven Central
 * and would need to be built from source — not worth a new, unusual build step for what is, at the
 * SQL level, an ordinary function call. AGE is reachable from any Postgres client (this app's
 * existing {@code org.postgresql:postgresql} driver, via {@code JdbcTemplate}) through
 * {@code ag_catalog.cypher()}, which takes the graph name, the Cypher text and one parameter
 * (an {@code agtype} map of bind variables) and returns rows shaped as {@code (v agtype)}.
 *
 * <p>Labels/indexes are deliberately NOT created by a Liquibase migration (see
 * {@code 022-lineage-graph.sql}'s comment) — {@link #ensureSchemaBlock()} creates them
 * idempotently on every rebuild instead, so a label added by a future milestone (M1j/M2/M3) needs
 * no migration and a manually dropped graph self-heals on the next rebuild.
 */
public final class AgeSql {

    private AgeSql() {
    }

    /**
     * Wraps {@code cypher} for execution via {@code ag_catalog.cypher()}. The lone {@code ?} is the
     * JDBC bind position for the Cypher statement's own parameters, serialized by
     * {@link AgeLineageGraphWriter} as a single {@code agtype} map.
     */
    public static String wrap(String cypher) {
        return "SELECT * FROM ag_catalog.cypher('" + LineageGraph.GRAPH_NAME + "', $$ " + cypher
                + " $$, ?) AS (v ag_catalog.agtype)";
    }

    /**
     * One idempotent {@code DO} block: creates the {@code secy_lineage} graph if it does not exist,
     * then for every {@link NodeLabel} a vertex label plus a GIN index on its {@code properties}
     * column, then for every {@link EdgeType} an edge label plus indexes on its {@code start_id}/
     * {@code end_id} columns. Safe to run on every rebuild — every step is guarded by an existence
     * check or {@code IF NOT EXISTS}.
     */
    public static String ensureSchemaBlock() {
        StringBuilder sb = new StringBuilder();
        String graph = LineageGraph.GRAPH_NAME;

        sb.append("do $$\n");
        sb.append("begin\n");
        sb.append("  if not exists (select 1 from ag_catalog.ag_graph where name = '").append(graph).append("') then\n");
        sb.append("    perform ag_catalog.create_graph('").append(graph).append("');\n");
        sb.append("  end if;\n\n");

        for (NodeLabel label : NodeLabel.values()) {
            String l = label.label();
            String idx = "idx_" + graph + "_" + l.toLowerCase(Locale.ROOT) + "_props";
            sb.append("  if not exists (select 1 from ag_catalog.ag_label lb join ag_catalog.ag_graph g on g.graphid = lb.graph")
                    .append(" where g.name = '").append(graph).append("' and lb.name = '").append(l).append("') then\n");
            sb.append("    perform ag_catalog.create_vlabel('").append(graph).append("', '").append(l).append("');\n");
            sb.append("  end if;\n");
            sb.append("  execute format('create index if not exists %I on ").append(graph)
                    .append(".%I using gin (properties)', '").append(idx).append("', '").append(l).append("');\n\n");
        }

        for (EdgeType type : EdgeType.values()) {
            String t = type.label();
            String startIdx = "idx_" + graph + "_" + t.toLowerCase(Locale.ROOT) + "_start";
            String endIdx = "idx_" + graph + "_" + t.toLowerCase(Locale.ROOT) + "_end";
            sb.append("  if not exists (select 1 from ag_catalog.ag_label lb join ag_catalog.ag_graph g on g.graphid = lb.graph")
                    .append(" where g.name = '").append(graph).append("' and lb.name = '").append(t).append("') then\n");
            sb.append("    perform ag_catalog.create_elabel('").append(graph).append("', '").append(t).append("');\n");
            sb.append("  end if;\n");
            sb.append("  execute format('create index if not exists %I on ").append(graph)
                    .append(".%I (start_id)', '").append(startIdx).append("', '").append(t).append("');\n");
            sb.append("  execute format('create index if not exists %I on ").append(graph)
                    .append(".%I (end_id)', '").append(endIdx).append("', '").append(t).append("');\n\n");
        }

        sb.append("end $$;");
        return sb.toString();
    }

}
