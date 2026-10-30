package net.jdesive.secy.lineage;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.TenantRepository;
import net.jdesive.secy.persistence.entity.Tenant;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * Orchestrates a full lineage-graph rebuild: plan, then replace, one tenant at a time
 * (ROADMAP.md, M1d).
 *
 * <p>Deliberately not {@code @Transactional} — {@link LineageSourceReader#read} opens its own
 * read-only transaction and {@link LineageGraphWriter#replaceTenantGraph} (in the real Postgres+AGE
 * implementation) opens its own write transaction against a Postgres connection; the two must never
 * share a connection, which a transaction spanning this method would force.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LineageRebuildService {

    private final LineageSourceReader reader;

    private final TenantRepository tenantRepository;

    private final ObjectProvider<LineageGraphWriter> writerProvider;

    private final LineageProperties properties;

    /** {@code true} only when both {@code secy.lineage.enabled=true} and a writer bean exists. */
    public boolean isAvailable() {
        return properties.isEnabled() && writerProvider.getIfAvailable() != null;
    }

    /** Plans (without writing) the graph for one tenant — the pure, fully-testable half of a rebuild. */
    public LineageGraphSnapshot plan(UUID tenantId) {
        return new LineagePlanner().plan(tenantId, reader.read(tenantId));
    }

    /**
     * Rebuilds every tenant's lineage graph, sorted by tenant id for a deterministic run order.
     * Fails fast on the first tenant that throws — every tenant processed before it has already
     * committed its own replace independently, so a partial run leaves those tenants' graphs
     * correctly rebuilt and the rest untouched (safe to simply re-run).
     *
     * @throws IllegalStateException when {@link #isAvailable()} is false
     */
    public IngestResult ingest(JobProgress progress) {
        LineageGraphWriter writer = writerProvider.getIfAvailable();
        if (!properties.isEnabled() || writer == null) {
            throw new IllegalStateException(
                    "Lineage graph is not available: secy.lineage.enabled=" + properties.isEnabled()
                            + ", writer=" + (writer == null ? "none" : writer.getClass().getSimpleName()));
        }

        List<Tenant> tenants = tenantRepository.findAll(Sort.by("id"));
        int totalNodes = 0;
        int totalEdges = 0;
        int tenantsProcessed = 0;

        for (Tenant tenant : tenants) {
            LineageGraphSnapshot snapshot = plan(tenant.getId());
            writer.replaceTenantGraph(snapshot);
            totalNodes += snapshot.nodes().size();
            totalEdges += snapshot.edges().size();
            tenantsProcessed++;
            progress.report(tenantsProcessed,
                    "Rebuilt lineage graph for " + tenantsProcessed + "/" + tenants.size() + " tenants");
        }

        String message = "Rebuilt lineage graph for " + tenantsProcessed + " tenant(s): "
                + totalNodes + " nodes, " + totalEdges + " edges";
        log.info(message);
        return new IngestResult(tenantsProcessed, message);
    }

}
