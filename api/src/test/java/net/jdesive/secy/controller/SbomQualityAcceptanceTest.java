package net.jdesive.secy.controller;

import com.jayway.jsonpath.JsonPath;
import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Product;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M1h acceptance bar: uploading a poor-quality CycloneDX/SPDX document scores it, surfaces the
 * score on {@code GET /products/{id}}, and raises exactly one {@code sbom-quality} finding; a
 * follow-up complete document scores 100, auto-resolves that finding, and exposes
 * {@code supplierName}/{@code documentAuthors} on the read path — with zero spillover into
 * lifecycle-drift/quantum-finding tables. Modeled on {@code CbomAcceptanceTest}'s
 * seed/upload/{@code jobRunner.poll()}/await-terminal pattern, since M1h's finding reconciliation
 * runs from a real after-commit listener that only fires once a job's transaction actually commits.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomQualityAcceptanceTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private SbomQualityFindingRepository sbomQualityFindingRepository;

    @Autowired
    private LifecycleDriftFindingRepository lifecycleDriftFindingRepository;

    @Autowired
    private QuantumVulnerabilityFindingRepository quantumFindingRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository compromiseFindingRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        sbomQualityFindingRepository.deleteAll();
        lifecycleDriftFindingRepository.deleteAll();
        quantumFindingRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("sbom-quality-acceptance-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    @WithMockUser
    void aPoorCycloneDxDocumentScores33AndRaisesOneFindingThenAnUpgradeResolvesIt() throws Exception {
        awaitJobTerminal(uploadAndGetJobId("cyclonedx-poor.json", productId));

        String productBody = mockMvc.perform(get("/products/{id}", productId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sboms[0].quality.score").value(33))
                .andExpect(jsonPath("$.sboms[0].quality.hasAuthor").value(false))
                .andExpect(jsonPath("$.sboms[0].quality.missingElements").isArray())
                .andReturn().getResponse().getContentAsString();
        assertThat(productBody).contains("\"SUPPLIER\"");

        mockMvc.perform(get("/sbom-quality").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].quality.score").value(33))
                .andExpect(jsonPath("$.content[0].scoreThreshold").value(70))
                .andExpect(jsonPath("$.content[0].lifecycleState").value("ACTIVE"));

        String listBody = mockMvc.perform(get("/sbom-quality").param("productId", productId.toString()))
                .andReturn().getResponse().getContentAsString();
        String findingId = JsonPath.read(listBody, "$.content[0].id");
        mockMvc.perform(get("/sbom-quality/{id}", findingId))
                .andExpect(status().isOk());

        // Upgrade: a fully-complete document to the same (unstaged) slot.
        awaitJobTerminal(uploadAndGetJobId("cyclonedx-complete.json", productId));

        String upgradedProductBody = mockMvc.perform(get("/products/{id}", productId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(upgradedProductBody).contains("\"score\":100").contains("\"documentAuthors\":\"Acme Build Team\"")
                .contains("\"supplierName\":\"Acme\"");

        mockMvc.perform(get("/sbom-quality").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        mockMvc.perform(get("/sbom-quality")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(findingId));

        // Zero spillover into unrelated finding tables.
        assertThat(lifecycleDriftFindingRepository.findAll()).isEmpty();
        assertThat(quantumFindingRepository.findAll()).isEmpty();
    }

    @Test
    @WithMockUser
    void spdxParityCompleteScoresNoFindingPoorRaisesOne() throws Exception {
        Product completeProduct = new Product();
        completeProduct.setName("spdx-complete-" + UUID.randomUUID());
        UUID completeProductId = productRepository.save(completeProduct).getId();
        awaitJobTerminal(uploadAndGetJobId("spdx-2.3-complete.json", completeProductId));

        mockMvc.perform(get("/sbom-quality").param("productId", completeProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
        mockMvc.perform(get("/products/{id}", completeProductId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sboms[0].quality.score").value(100));

        Product poorProduct = new Product();
        poorProduct.setName("spdx-poor-" + UUID.randomUUID());
        UUID poorProductId = productRepository.save(poorProduct).getId();
        awaitJobTerminal(uploadAndGetJobId("spdx-2.3-poor.json", poorProductId));

        mockMvc.perform(get("/sbom-quality").param("productId", poorProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @WithMockUser
    void unknownFindingIdReturns404() throws Exception {
        mockMvc.perform(get("/sbom-quality/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ---------------------------------------------------------------------- */
    /* Helpers                                                                */
    /* ---------------------------------------------------------------------- */

    private UUID uploadAndGetJobId(String fixture, UUID targetProductId) throws Exception {
        String responseBody = mockMvc.perform(post("/sbom/{productId}/sboms", targetProductId)
                        .param("productVersion", "1.0.0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(fixture)))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        UUID jobId = extractJobId(responseBody);
        jobRunner.poll();
        return jobId;
    }

    private static UUID extractJobId(String responseBody) {
        int start = responseBody.indexOf("\"id\":\"") + 6;
        int end = responseBody.indexOf('"', start);
        return UUID.fromString(responseBody.substring(start, end));
    }

    private void awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        Job job = jobRepository.findById(id).orElseThrow();
        assertThat(job.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/quality/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
