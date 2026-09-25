package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code ?stage=} upload param (M1e) on both {@code POST /sbom/{productId}/sboms} and
 * {@code POST /sbom}. Modeled on {@code SbomUploadFormatTest}/{@code TagDrivenSbomUploadTest}, which
 * own the equivalent format-detection contract.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@org.springframework.transaction.annotation.Transactional
class SbomLifecycleStageUploadTest {

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
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private net.jdesive.secy.persistence.AssetRepository assetRepository;

    @Autowired
    private net.jdesive.secy.persistence.JobRepository jobRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("stage-upload-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    void stageBuildOnTheManualEndpointSetsBuild() throws Exception {
        manualUpload("cyclonedx-mixed.json", "build").andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    @Test
    void stageDeployedOnTheTaggedEndpointSetsDeployed() throws Exception {
        taggedUpload("cyclonedx-mixed.json", "secy:product=x", "DEPLOYED").andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getLifecycleStage()).isEqualTo(SbomLifecycleStage.DEPLOYED);
        assertThat(placeholder.getProduct().getName()).isEqualTo("x");
    }

    @Test
    void anUnrecognisedStageIs400WithTheAllowedValuesAndNothingChanges() throws Exception {
        long jobsBefore = jobRepository.count();
        long sbomsBefore = sbomRepository.count();
        long productsBefore = productRepository.count();

        manualUpload("cyclonedx-mixed.json", "prod")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("SOURCE")))
                .andExpect(jsonPath("$.message", containsString("BUILD")))
                .andExpect(jsonPath("$.message", containsString("ANALYZED")))
                .andExpect(jsonPath("$.message", containsString("DEPLOYED")));

        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
        assertThat(sbomRepository.count()).isEqualTo(sbomsBefore);
        assertThat(productRepository.count()).isEqualTo(productsBefore);
    }

    @Test
    void anUnrecognisedStageOnTheTaggedEndpointIs400WithNoProductCreated() throws Exception {
        long productsBefore = productRepository.count();

        taggedUpload("cyclonedx-mixed.json", "secy:product=should-not-exist", "prod")
                .andExpect(status().isBadRequest());

        assertThat(productRepository.count()).isEqualTo(productsBefore);
        assertThat(productRepository.findByName("should-not-exist")).isEmpty();
        assertThat(sbomRepository.findAll()).isEmpty();
    }

    @Test
    void noStageParamWithACycloneDxLifecyclesFixtureUsesTheDocumentStage() throws Exception {
        manualUpload("cyclonedx-build-lifecycle.json", null).andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        assertThat(placeholder.getLifecycleStage()).isEqualTo(SbomLifecycleStage.BUILD);
    }

    private SBOM onlySbom() {
        List<SBOM> all = sbomRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private ResultActions manualUpload(String fixture, String stage) throws Exception {
        var request = post("/sbom/{productId}/sboms", productId)
                .param("productVersion", "1.0.0")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture));
        if (stage != null) {
            request = request.param("stage", stage);
        }
        return mockMvc.perform(request);
    }

    private ResultActions taggedUpload(String fixture, String tagParam, String stage) throws Exception {
        var request = post("/sbom")
                .param("productVersion", "1.0.0")
                .param("tag", tagParam)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture));
        if (stage != null) {
            request = request.param("stage", stage);
        }
        return mockMvc.perform(request);
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
