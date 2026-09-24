package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.service.ProductService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code ProductController}'s M1a guards: the Unassigned bucket can't be deleted, its reserved name
 * can't be claimed by a manually-created product, a client can't flip a product's {@code unassigned}
 * flag through the request body, and {@code tagValue} is otherwise a normal writable field.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
class ProductControllerTest {

    /**
     * Not used to seed anything — cleared because a {@code compromise_finding} left behind by
     * another test class holds an FK into {@code sbom_component} / {@code asset_component} and
     * would block the deletes below (Phase 6).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ProductService productService;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private net.jdesive.secy.persistence.AssetRepository assetRepository;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
    }

    @Test
    void deletingTheUnassignedBucketIs409AndItSurvives() throws Exception {
        Product bucket = productService.getOrCreateUnassigned(net.jdesive.secy.persistence.entity.Tenant.DEFAULT_TENANT_ID);

        mockMvc.perform(delete("/products/{id}", bucket.getId()))
                .andExpect(status().isConflict());

        assertThat(productRepository.findById(bucket.getId())).isPresent();
    }

    @Test
    void deletingAnUnknownIdIsStillANoOp() throws Exception {
        mockMvc.perform(delete("/products/{id}", UUID.randomUUID()))
                .andExpect(status().isNoContent());
    }

    @Test
    void creatingAProductNamedUnassignedIs409() throws Exception {
        mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("name", "Unassigned"))))
                .andExpect(status().isConflict());

        mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("name", "UNASSIGNED"))))
                .andExpect(status().isConflict());
    }

    @Test
    void aClientSuppliedUnassignedFlagIsIgnoredOnCreate() throws Exception {
        String body = mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"totally-normal-product\",\"unassigned\":true}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = objectMapper.readTree(body);
        assertThat(json.get("unassigned").asBoolean()).isFalse();

        Product saved = productRepository.findByName("totally-normal-product").orElseThrow();
        assertThat(saved.isUnassigned()).isFalse();
    }

    @Test
    void tagValueIsPersistedWhenSupplied() throws Exception {
        mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "name", "billing-service",
                                "tagValue", "billing"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tagValue").value("billing"));

        Product saved = productRepository.findByName("billing-service").orElseThrow();
        assertThat(saved.getTagValue()).isEqualTo("billing");
    }

    @Test
    void aTagValueEqualToUnassignedIs409() throws Exception {
        mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "name", "some-product",
                                "tagValue", "unassigned"))))
                .andExpect(status().isConflict());
    }
}
