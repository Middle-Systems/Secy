package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.entity.Product;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Every synchronous rejection {@code POST /vex} is responsible for — each one must leave no job and
 * no document row behind, exactly like {@code SbomUploadFormatTest}'s equivalent guarantee.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "secy.vex.max-document-bytes=4096")
class VexUploadHardeningTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private ProductRepository productRepository;

    @BeforeEach
    void seed() {
        vexDocumentRepository.deleteAll();
        jobRepository.deleteAll();
    }

    @Test
    @WithMockUser
    void oversizedBodyIs413() throws Exception {
        String bigStatement = "\"x\":\"" + "a".repeat(5000) + "\"";
        String body = "{\"@context\": \"https://openvex.dev/ns/v0.2.0\", \"" + bigStatement + "\", \"statements\": []}";

        mockMvc.perform(post("/vex").param("origin", "TENANT")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isPayloadTooLarge());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void malformedJsonIs400() throws Exception {
        mockMvc.perform(post("/vex").param("origin", "TENANT")
                        .contentType(MediaType.APPLICATION_JSON).content("{ not valid json"))
                .andExpect(status().isBadRequest());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void missingOriginIs400() throws Exception {
        mockMvc.perform(post("/vex")
                        .contentType(MediaType.APPLICATION_JSON).content(minimalOpenVex()))
                .andExpect(status().isBadRequest());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void badOriginIs400() throws Exception {
        mockMvc.perform(post("/vex").param("origin", "NOBODY")
                        .contentType(MediaType.APPLICATION_JSON).content(minimalOpenVex()))
                .andExpect(status().isBadRequest());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void unknownProductIdIs404() throws Exception {
        mockMvc.perform(post("/vex").param("origin", "TENANT").param("productId", UUID.randomUUID().toString())
                        .contentType(MediaType.APPLICATION_JSON).content(minimalOpenVex()))
                .andExpect(status().isNotFound());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void unassignedBucketProductIdIs400() throws Exception {
        Product unassigned = new Product();
        unassigned.setName(Product.UNASSIGNED_NAME + "-" + UUID.randomUUID());
        unassigned.setUnassigned(true);
        UUID id = productRepository.save(unassigned).getId();

        mockMvc.perform(post("/vex").param("origin", "TENANT").param("productId", id.toString())
                        .contentType(MediaType.APPLICATION_JSON).content(minimalOpenVex()))
                .andExpect(status().isBadRequest());

        assertNothingPersisted();
    }

    @Test
    @WithMockUser
    void cycloneDxSbomWithoutVulnerabilitiesIs400() throws Exception {
        String body = """
                {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:cccccccc-cccc-cccc-cccc-cccccccccccc", "components": []}
                """;
        mockMvc.perform(post("/vex").param("origin", "TENANT")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());

        assertNothingPersisted();
    }

    private void assertNothingPersisted() {
        assertThat(jobRepository.count()).isZero();
        assertThat(vexDocumentRepository.count()).isZero();
    }

    private static String minimalOpenVex() {
        return """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://acme.example/vex/hardening",
                  "statements": [
                    {
                      "vulnerability": {"name": "CVE-2099-7401"},
                      "products": [{"@id": "pkg:npm/x@1.0.0"}],
                      "status": "affected"
                    }
                  ]
                }
                """;
    }

}
