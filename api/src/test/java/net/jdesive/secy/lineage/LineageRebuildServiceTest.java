package net.jdesive.secy.lineage;

import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Tenant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link LineageRebuildService} exercised end to end against H2, with an in-memory
 * {@link LineageGraphWriter} test double standing in for {@link AgeLineageGraphWriter} — proves
 * the orchestration (plan every tenant, replace semantics, idempotence) without needing a real
 * Postgres+AGE instance (ROADMAP.md, M1d). See {@code LineageRebuildServiceAvailabilityTest} for
 * the disabled/no-writer cases, which don't need a Spring context at all.
 */
@SpringBootTest
@TestPropertySource(properties = "secy.lineage.enabled=true")
class LineageRebuildServiceTest {

    @Autowired
    private LineageRebuildService lineageRebuildService;

    @Autowired
    private InMemoryLineageGraphWriter writer;

    @Autowired
    private ProductRepository productRepository;

    @BeforeEach
    void cleanUp() {
        writer.clear();
        productRepository.deleteAll();
    }

    @Test
    void isAvailableWhenEnabledAndAWriterExists() {
        assertThat(lineageRebuildService.isAvailable()).isTrue();
    }

    @Test
    void ingestRebuildsEveryTenantAndIsIdempotent() {
        Product product = new Product();
        product.setName("Rebuild-Test-" + UUID.randomUUID());
        productRepository.save(product);

        IngestResult first = lineageRebuildService.ingest(JobProgress.NOOP);
        assertThat(first.itemsProcessed()).isGreaterThanOrEqualTo(1); // at least the default tenant

        LineageGraphSnapshot afterFirst = writer.snapshots().get(Tenant.DEFAULT_TENANT_ID);
        assertThat(afterFirst).isNotNull();
        assertThat(afterFirst.nodes()).extracting(GraphNode::key).contains(product.getId().toString());

        // A pre-seeded junk snapshot for the default tenant is fully replaced, not merged.
        writer.replaceTenantGraph(new LineageGraphSnapshot(Tenant.DEFAULT_TENANT_ID, List.of(), List.of()));
        assertThat(writer.snapshots().get(Tenant.DEFAULT_TENANT_ID).nodes()).isEmpty();

        lineageRebuildService.ingest(JobProgress.NOOP);
        LineageGraphSnapshot afterSecond = writer.snapshots().get(Tenant.DEFAULT_TENANT_ID);
        assertThat(afterSecond).isEqualTo(afterFirst);
    }

    @TestConfiguration
    static class InMemoryWriterConfig {

        @Bean
        @Primary
        InMemoryLineageGraphWriter inMemoryLineageGraphWriter() {
            return new InMemoryLineageGraphWriter();
        }

    }

    /** Stores the last snapshot written per tenant, with replace (not merge) semantics. */
    static class InMemoryLineageGraphWriter implements LineageGraphWriter {

        private final Map<UUID, LineageGraphSnapshot> snapshots = new ConcurrentHashMap<>();

        @Override
        public void replaceTenantGraph(LineageGraphSnapshot snapshot) {
            snapshots.put(snapshot.tenantId(), snapshot);
        }

        Map<UUID, LineageGraphSnapshot> snapshots() {
            return snapshots;
        }

        void clear() {
            snapshots.clear();
        }

    }

}
