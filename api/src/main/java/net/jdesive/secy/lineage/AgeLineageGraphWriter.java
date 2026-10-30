package net.jdesive.secy.lineage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.lineage.model.LineageGraphSnapshot;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCallback;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Types;
import java.util.List;

/**
 * Writes a {@link LineageGraphSnapshot} into Apache AGE via plain SQL — {@code ag_catalog.cypher()}
 * calls through the {@link JdbcTemplate} the app already has, not a dedicated AGE driver (see
 * {@link AgeSql}'s Javadoc for why there is no such dependency in {@code build.gradle}).
 *
 * <p><b>Only user-verifiable, not exercised by {@code ./gradlew test}.</b> Every other class in
 * this package runs against plain JPQL/H2 or is pure Java; this one talks to AGE-specific SQL
 * functions ({@code ag_catalog.cypher}, {@code create_graph}, {@code create_vlabel}, ...) that do
 * not exist outside a real Postgres with the AGE extension loaded. Bean only exists when
 * {@code secy.lineage.enabled=true} — see the {@link ConditionalOnProperty} below — which is
 * {@code false} by default precisely so a Postgres without AGE never even attempts this path. See
 * {@code AgeLineageGraphWriterIT} for the opt-in integration test that exercises this class for
 * real, and {@code api/README.md}'s lineage-graph runbook for how to run it.
 *
 * <p>Postgres's own MVCC gives {@link #replaceTenantGraph} its atomicity for free: every statement
 * the delete-then-recreate sequence issues runs in one transaction, so a concurrent reader either
 * sees the whole prior graph or the whole new one, never a partial rewrite.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "secy.lineage.enabled", havingValue = "true")
public class AgeLineageGraphWriter implements LineageGraphWriter {

    private final JdbcTemplate jdbc;

    private final TransactionTemplate transactionTemplate;

    private final ObjectMapper mapper;

    private final LineageProperties props;

    private final CypherRenderer renderer = new CypherRenderer();

    public AgeLineageGraphWriter(JdbcTemplate jdbc, PlatformTransactionManager txManager,
                                  ObjectMapper mapper, LineageProperties props) {
        this.jdbc = jdbc;
        this.transactionTemplate = new TransactionTemplate(txManager);
        this.mapper = mapper;
        this.props = props;
    }

    @Override
    public void replaceTenantGraph(LineageGraphSnapshot snapshot) {
        List<CypherStatement> statements = renderer.renderReplace(snapshot, props.getBatchSize());
        transactionTemplate.executeWithoutResult(status -> {
            String library = props.getAgeLibrary();
            if (library != null && !library.isBlank()) {
                // Validated at binding time (LineageProperties) against a safe filename/path
                // shape -- this string is concatenated directly into the LOAD statement, since
                // Postgres extensions have no parameterized-load form.
                jdbc.execute("LOAD '" + library + "'");
            }
            // LOCAL: this is a pooled Hikari connection shared with plain JPA traffic once this
            // transaction commits. A non-LOCAL SET would leak ag_catalog onto the search path for
            // whatever unrelated query borrows the connection next.
            jdbc.execute("SET LOCAL search_path = ag_catalog, \"$user\", public");
            jdbc.execute(AgeSql.ensureSchemaBlock());
            for (CypherStatement statement : statements) {
                executeCypher(statement);
            }
        });
        log.info("Replaced lineage graph for tenant {}: {} nodes, {} edges",
                snapshot.tenantId(), snapshot.nodes().size(), snapshot.edges().size());
    }

    /**
     * One {@code ag_catalog.cypher()} call. Not {@code jdbc.batchUpdate}: {@code cypher()} returns
     * a result set, and pgjdbc refuses a {@code SELECT} inside a JDBC batch.
     */
    private void executeCypher(CypherStatement statement) {
        String sql = AgeSql.wrap(statement.cypher());
        jdbc.execute(sql, (PreparedStatementCallback<Void>) ps -> {
            try {
                String json = mapper.writeValueAsString(statement.params());
                ps.setObject(1, json, Types.OTHER);
                ps.execute();
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Failed to serialize Cypher params as agtype", e);
            }
            return null;
        });
    }

}
