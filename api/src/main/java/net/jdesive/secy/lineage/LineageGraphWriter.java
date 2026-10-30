package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.LineageGraphSnapshot;

/**
 * Writes a planned {@link LineageGraphSnapshot} to the graph store.
 *
 * <p>Contract: {@link #replaceTenantGraph} atomically makes the tenant's subgraph equal to the
 * given snapshot, independent of whatever the graph held before — the tenant-wide delete that
 * always leads {@link CypherRenderer#renderReplace} is what makes this true regardless of prior
 * state (rebuildability property P2, ROADMAP.md's M1d plan).
 *
 * <p>The only production implementation is {@link AgeLineageGraphWriter}, active only when
 * {@code secy.lineage.enabled=true}; tests substitute an in-memory fake so
 * {@code LineageRebuildService} is fully exercised without a real Postgres+AGE instance.
 */
public interface LineageGraphWriter {

    void replaceTenantGraph(LineageGraphSnapshot snapshot);

}
