package net.jdesive.secy.lineage;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.lineage.model.GraphEdge;
import net.jdesive.secy.lineage.model.GraphNode;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link AgeLineageGraphWriter} against a REAL Postgres with Apache AGE installed.
 *
 * <p><b>Skipped automatically everywhere this session's environment runs</b> (no Docker, no
 * Postgres) and in every normal CI run — {@link EnabledIfEnvironmentVariable} only enables it when
 * {@code SECY_AGE_IT_URL} is set. See {@code api/README.md}'s lineage-graph runbook for how to
 * point it at a real instance:
 *
 * <pre>
 * SECY_AGE_IT_URL=jdbc:postgresql://localhost:5433/secy \
 * SECY_AGE_IT_USER=secy \
 * SECY_AGE_IT_PASSWORD=secy \
 * ./gradlew test --tests net.jdesive.secy.lineage.AgeLineageGraphWriterIT
 * </pre>
 *
 * <p>No Spring context — builds a plain {@link DriverManagerDataSource}/{@link JdbcTemplate}/
 * {@link DataSourceTransactionManager} directly and constructs {@link AgeLineageGraphWriter}
 * through its constructor, exactly as the plan requires. Uses a random tenant id and always writes
 * an empty snapshot for it in {@link #cleanUp}, so pointing this at a real dev database can never
 * leave it polluted.
 */
@EnabledIfEnvironmentVariable(named = "SECY_AGE_IT_URL", matches = ".+")
class AgeLineageGraphWriterIT {

    private UUID tenantId;

    private AgeLineageGraphWriter writer;

    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl(System.getenv("SECY_AGE_IT_URL"));
        dataSource.setUsername(System.getenv().getOrDefault("SECY_AGE_IT_USER", "secy"));
        dataSource.setPassword(System.getenv().getOrDefault("SECY_AGE_IT_PASSWORD", "secy"));

        jdbc = new JdbcTemplate(dataSource);
        DataSourceTransactionManager txManager = new DataSourceTransactionManager(dataSource);

        LineageProperties properties = new LineageProperties();
        properties.setEnabled(true);
        properties.setAgeLibrary("age");
        properties.setBatchSize(500);

        writer = new AgeLineageGraphWriter(jdbc, txManager, new ObjectMapper(), properties);
    }

    @AfterEach
    void cleanUp() {
        if (writer != null) {
            writer.replaceTenantGraph(new LineageGraphSnapshot(tenantId, List.of(), List.of()));
        }
    }

    @Test
    void replaceTenantGraphWritesNodesAndEdgesIntoRealAge() {
        String productKey = UUID.randomUUID().toString();
        String sbomKey = UUID.randomUUID().toString();
        GraphNode product = new GraphNode(NodeLabel.PRODUCT, productKey,
                Map.of("tenant_id", tenantId.toString(), "pg_id", productKey, "name", "IT Product"));
        GraphNode sbom = new GraphNode(NodeLabel.SBOM, sbomKey,
                Map.of("tenant_id", tenantId.toString(), "pg_id", sbomKey));
        GraphEdge edge = new GraphEdge(EdgeType.HAS_SBOM, product.ref(), sbom.ref());

        LineageGraphSnapshot snapshot = new LineageGraphSnapshot(tenantId, List.of(product, sbom), List.of(edge));

        writer.replaceTenantGraph(snapshot);

        Long count = jdbc.queryForObject(
                "SELECT count(*) FROM ag_catalog.cypher('secy_lineage', $$ "
                        + "MATCH (n {tenant_id: '" + tenantId + "'}) RETURN n $$) AS (v ag_catalog.agtype)",
                Long.class);
        assertThat(count).isEqualTo(2L);
    }

}
