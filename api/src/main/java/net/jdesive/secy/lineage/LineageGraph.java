package net.jdesive.secy.lineage;

/**
 * The one Apache AGE graph Secy writes lineage into (ROADMAP.md, M1d — "Lineage graph (Apache
 * AGE)").
 *
 * <p><b>Not configurable.</b> The name is interpolated directly into Cypher/SQL text passed to
 * {@code ag_catalog.cypher(...)} — AGE has no way to bind a graph name as a query parameter — so
 * making it a property would only invite an injection surface for no real flexibility: there is
 * exactly one lineage graph per Secy instance, tenant isolation is by the {@code tenant_id}
 * property on every node and edge, not by a separate graph per tenant.
 */
public final class LineageGraph {

    public static final String GRAPH_NAME = "secy_lineage";

    private LineageGraph() {
    }

}
