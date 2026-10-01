/**
 * The M1d lineage graph: a queryable index over Postgres data, rebuildable from it on demand, on
 * top of Apache AGE (ROADMAP.md, M1d — "Lineage graph (Apache AGE)").
 *
 * <h2>One-way flow (rebuildability property P3)</h2>
 *
 * <p>Data flows in exactly one direction: Postgres (via {@link
 * net.jdesive.secy.lineage.LineageSourceReader}) → {@link net.jdesive.secy.lineage.LineagePlanner}
 * → {@link net.jdesive.secy.lineage.CypherRenderer} → {@link
 * net.jdesive.secy.lineage.LineageGraphWriter}. Nothing in this package, or anywhere else in the
 * codebase, reads the graph to write Postgres. Postgres remains the sole system of record; the
 * graph is a derived, disposable index that a rebuild can always regenerate from scratch. A future
 * milestone that wants to query the graph (there is no read endpoint in M1d) must not use that
 * query result to update a Postgres row — that would make the graph a second source of truth,
 * which is exactly what this design avoids.
 *
 * <h2>What ships in M1d vs. what is deferred</h2>
 *
 * <p>See {@code ROADMAP.md}'s M1d section for the full split of what is real, tested code in this
 * package (the planner, renderer, SQL builder, JPA reader, rebuild service, job/controller wiring)
 * versus what is real but only user-verifiable against a live Postgres+AGE instance (migration
 * {@code 022}, {@link net.jdesive.secy.lineage.AgeLineageGraphWriter}'s actual JDBC execution, the
 * Postgres Docker image change) versus what is explicitly deferred (live incremental sync, Repo/
 * Build nodes, Finding/ActionItem, Owner nodes, any graph read API or UI). Dependency edges shipped
 * in M1l (ROADMAP.md — "Dependency graph preserved") as {@link net.jdesive.secy.lineage.EdgeType#DEPENDS_ON},
 * read from {@code sbom_component_dependency} by {@link net.jdesive.secy.lineage.LineageSourceReader}
 * and emitted by {@link net.jdesive.secy.lineage.LineagePlanner}.
 */
package net.jdesive.secy.lineage;
