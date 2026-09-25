package net.jdesive.secy.controller;

import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMComponentCryptoAssetRepository;
import net.jdesive.secy.persistence.SBOMRepository;
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
 * The M1g acceptance bar: a CycloneDX 1.6 document with embedded {@code cryptographic-asset}
 * components ingests cleanly, inventories every crypto asset at {@code GET /cbom/assets}, and raises
 * exactly one quantum-vulnerability finding for the RSA key — with zero spillover into
 * vulnerability/compromise/lifecycle-drift findings. Modeled on {@code LifecycleDriftAcceptanceTest}'s
 * seed/upload/{@code jobRunner.poll()}/await-terminal pattern, since the M1g finding reconciliation
 * runs from a real after-commit listener that only fires once a job's transaction actually commits.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CbomAcceptanceTest {

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
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository compromiseFindingRepository;

    @Autowired
    private LifecycleDriftFindingRepository lifecycleDriftFindingRepository;

    @Autowired
    private QuantumVulnerabilityFindingRepository quantumFindingRepository;

    @Autowired
    private SBOMComponentCryptoAssetRepository cryptoAssetRepository;

    @Autowired
    private AssetRepository assetRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        quantumFindingRepository.deleteAll();
        lifecycleDriftFindingRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("cbom-acceptance-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    @WithMockUser
    void aCycloneDx16DocumentWithEmbeddedCbomInventoriesAssetsAndRaisesOneQuantumFinding() throws Exception {
        awaitJobTerminal(uploadAndGetJobId("cyclonedx-1.6-rsa-aes-keys.json", productId));

        String assetsBody = mockMvc.perform(get("/cbom/assets").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andReturn().getResponse().getContentAsString();
        assertThat(assetsBody).contains("RSA-2048").contains("AES-256")
                .contains("\"quantumStatus\":\"VULNERABLE\"")
                .contains("\"quantumStatus\":\"NOT_VULNERABLE\"");

        String findingsBody = mockMvc.perform(get("/cbom/quantum-findings").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cryptoIdentityKey").value("cbom:related-crypto-material:rsa-2048"))
                .andExpect(jsonPath("$.content[0].algorithmFamily").value("RSA"))
                .andExpect(jsonPath("$.content[0].assetType").value("RELATED_CRYPTO_MATERIAL"))
                .andReturn().getResponse().getContentAsString();
        assertThat(findingsBody).isNotBlank();

        UUID rsaAssetId = cryptoAssetRepository.findAll().stream()
                .filter(a -> "RSA".equals(a.getQuantumFamily() == null ? null : a.getQuantumFamily().name()))
                .findFirst().orElseThrow().getId();
        String detailBody = mockMvc.perform(get("/cbom/assets/{id}", rsaAssetId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(detailBody).doesNotContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC-FAKE");

        // Zero spillover: crypto components must not feed vulnerability correlation, compromise
        // detection, or lifecycle drift.
        assertThat(alertRepository.findAll()).isEmpty();
        assertThat(compromiseFindingRepository.findAll()).isEmpty();
        assertThat(lifecycleDriftFindingRepository.findAll()).isEmpty();

        // The ordinary library component still ingests normally.
        UUID sbomId = sbomRepository.findAllByProductIdAndActiveTrue(productId).get(0).getId();
        assertThat(sbomRepository.findByIdWithComponents(sbomId).orElseThrow().getComponents())
                .extracting("name").contains("lodash");
    }

    @Test
    @WithMockUser
    void reUploadingWithoutTheRsaKeyAutoResolvesTheFinding() throws Exception {
        awaitJobTerminal(uploadAndGetJobId("cyclonedx-1.6-rsa-aes-keys.json", productId));
        assertThat(quantumFindingRepository.findAll()).hasSize(1);

        awaitJobTerminal(uploadAndGetJobId("cyclonedx-1.6-standalone-cbom-aes-only.json", productId));

        mockMvc.perform(get("/cbom/quantum-findings")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cryptoIdentityKey").value("cbom:related-crypto-material:rsa-2048"));
    }

    @Test
    @WithMockUser
    void aStandaloneCbomIngestsCleanlyAndProducesFindings() throws Exception {
        Product standaloneProduct = new Product();
        standaloneProduct.setName("cbom-standalone-" + UUID.randomUUID());
        UUID standaloneProductId = productRepository.save(standaloneProduct).getId();

        awaitJobTerminal(uploadAndGetJobId("cyclonedx-1.6-standalone-cbom.json", standaloneProductId));

        mockMvc.perform(get("/cbom/assets").param("productId", standaloneProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));
        mockMvc.perform(get("/cbom/quantum-findings").param("productId", standaloneProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @WithMockUser
    void aCycloneDx15UploadProducesNoAssetsOrFindings() throws Exception {
        awaitJobTerminal(uploadAndGetJobId("cyclonedx-1.5-crypto-typed.json", productId));

        mockMvc.perform(get("/cbom/assets").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
        mockMvc.perform(get("/cbom/quantum-findings").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
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
        try (InputStream in = new ClassPathResource("cbom/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
