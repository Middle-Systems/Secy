package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SourceConnectorRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.persistence.entity.SourceConnectorType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The plain CRUD surface of {@code /connectors} — creation, listing, detail and delete. The actual
 * sync ({@code POST /connectors/{id}/sync} and the {@code CONNECTOR_SYNC} job it queues) is
 * {@code ConnectorSyncJobFlowTest}'s job; this class only pins the resource contract.
 *
 * <p>Every test is {@code @Transactional} so nothing it creates survives past its own rollback —
 * the H2 database is shared across every {@code @SpringBootTest} context in the run.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SourceConnectorControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SourceConnectorRepository sourceConnectorRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @BeforeEach
    void seed() {
        sourceConnectorRepository.deleteAll();
        // A compromise_finding left behind by another test class holds an FK into sbom_component and
        // would block productRepository.deleteAll() below -- the H2 database is shared across every
        // @SpringBootTest context in the run, same reason ConnectorSyncJobFlowTest clears it.
        findingRepository.deleteAll();
        productRepository.deleteAll();
    }

    @Test
    @Transactional
    @WithMockUser
    void createDoesNotTriggerASyncAndStartsQueuedWithNoLastSyncedAt() throws Exception {
        mockMvc.perform(post("/connectors")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"GITHUB","name":"Acme org","scope":"acme-corp"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.type").value("GITHUB"))
                .andExpect(jsonPath("$.name").value("Acme org"))
                .andExpect(jsonPath("$.scope").value("acme-corp"))
                .andExpect(jsonPath("$.status").value(SourceConnector.STATUS_QUEUED))
                .andExpect(jsonPath("$.lastSyncedAt").doesNotExist())
                .andExpect(jsonPath("$.id").isNotEmpty());

        assertThat(sourceConnectorRepository.count()).isEqualTo(1);
    }

    @Test
    @Transactional
    @WithMockUser
    void createPersistsAnOptionalRepoAllowlist() throws Exception {
        String body = mockMvc.perform(post("/connectors")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"GITHUB","name":"Payments team","scope":"acme-corp",
                                 "repoAllowlist":["acme-corp/payments-api","acme-corp/payments-worker"]}
                                """))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        mockMvc.perform(get("/connectors").param("size", "50"))
                .andExpect(jsonPath("$.content[0].repoAllowlist",
                        containsInAnyOrder("acme-corp/payments-api", "acme-corp/payments-worker")));

        assertThat(body).contains("payments-api");
    }

    @Test
    @Transactional
    @WithMockUser
    void listIsPagedNewestFirst() throws Exception {
        connector("First", "org-a");
        connector("Second", "org-b");

        mockMvc.perform(get("/connectors"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content[0].name").value("Second"))
                .andExpect(jsonPath("$.content[1].name").value("First"));
    }

    @Test
    @Transactional
    @WithMockUser
    void detailReturnsTheConnectorOr404() throws Exception {
        UUID id = connector("Acme org", "acme-corp");

        mockMvc.perform(get("/connectors/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.scope").value("acme-corp"));

        mockMvc.perform(get("/connectors/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    @Test
    @Transactional
    @WithMockUser
    void deleteRemovesTheConnectorButNotTheProductsItIntroduced() throws Exception {
        UUID id = connector("Acme org", "acme-corp");

        // Stands in for "a product this connector previously synced" — deleting the connector must
        // not touch it, since a connector row carries no FK to what it created (see the class
        // Javadoc on SourceConnectorController#delete).
        Product product = new Product();
        product.setName("acme-corp/already-synced-repo");
        productRepository.save(product);

        mockMvc.perform(delete("/connectors/{id}", id)).andExpect(status().isNoContent());

        assertThat(sourceConnectorRepository.findById(id)).isEmpty();
        assertThat(productRepository.findByName("acme-corp/already-synced-repo")).isPresent();
    }

    @Test
    @Transactional
    @WithMockUser
    void deletingAnUnknownConnectorIs404() throws Exception {
        mockMvc.perform(delete("/connectors/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    private UUID connector(String name, String scope) {
        SourceConnector connector = new SourceConnector();
        connector.setType(SourceConnectorType.GITHUB);
        connector.setName(name);
        connector.setScope(scope);
        return sourceConnectorRepository.saveAndFlush(connector).getId();
    }

}
