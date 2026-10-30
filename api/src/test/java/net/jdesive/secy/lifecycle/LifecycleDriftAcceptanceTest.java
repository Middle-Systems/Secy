package net.jdesive.secy.lifecycle;

import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M1 acceptance bar for M1e: "one SBOM per lifecycle stage ingests cleanly into one deduplicated
 * inventory" and "a deliberately injected build-only component produces a drift finding" — the two
 * most important tests in this milestone. Modeled on {@code SbomUploadJobFlowTest}'s
 * seed/upload/{@code jobRunner.poll()}/await-terminal pattern, since the diff runs from a real
 * after-commit listener that only fires once a job's transaction actually commits.
 *
 * <p>The KEV-ranking acceptance criterion is M1i's job (scoring); this class instead proves the data
 * precondition M1i will need — see {@code StagedCorrelationScopeTest} for that (a lifecycleStage is
 * readable off {@code alert.component.sbom}), which is out of scope for this class.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LifecycleDriftAcceptanceTest {

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
    private AssetRepository assetRepository;

    private UUID productId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        lifecycleDriftFindingRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("lifecycle-drift-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    @WithMockUser
    void aDeliberatelyInjectedBuildOnlyComponentProducesASourceVsBuildDriftFinding() throws Exception {
        uploadAndAwait("source.cdx.json", null);
        uploadAndAwait("build.cdx.json", null);

        List<LifecycleDriftFinding> findings = lifecycleDriftFindingRepository.findAll();
        assertThat(findings).hasSize(1);
        LifecycleDriftFinding finding = findings.get(0);
        assertThat(finding.getStagePair().name()).isEqualTo("SOURCE_BUILD");
        assertThat(finding.getDriftKind().name()).isEqualTo("UNEXPECTED_COMPONENT");
        assertThat(finding.getIdentityKey()).isEqualTo("npm/acme-internal-utils");
        assertThat(finding.getLifecycleState().name()).isEqualTo("ACTIVE");

        SBOM sourceSbom = onlyActiveSbomFor(SbomLifecycleStage.SOURCE);
        SBOM buildSbom = onlyActiveSbomFor(SbomLifecycleStage.BUILD);
        assertThat(finding.getBaselineSbomId()).isEqualTo(sourceSbom.getId());
        assertThat(finding.getObservedSbomId()).isEqualTo(buildSbom.getId());

        // Different roots ("acme-web" vs "acme-web-build") must not themselves produce a finding, and
        // both SBOMs must stay active — the whole point of the per-(product,stage) slot.
        assertThat(sourceSbom.isActive()).isTrue();
        assertThat(buildSbom.isActive()).isTrue();

        assertThat(mockMvc.perform(get("/lifecycle-drift").param("productId", productId.toString()))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString())
                .contains("npm/acme-internal-utils")
                .contains("DEPENDENCY_CONFUSION_OR_BUILD_INJECTION");
    }

    @Test
    @WithMockUser
    void theSameFindingAppearsWhenBuildArrivesBeforeSource() throws Exception {
        uploadAndAwait("build.cdx.json", null);
        uploadAndAwait("source.cdx.json", null);

        List<LifecycleDriftFinding> findings = lifecycleDriftFindingRepository.findAll();
        assertThat(findings).hasSize(1);
        LifecycleDriftFinding finding = findings.get(0);
        assertThat(finding.getStagePair().name()).isEqualTo("SOURCE_BUILD");
        assertThat(finding.getDriftKind().name()).isEqualTo("UNEXPECTED_COMPONENT");
        assertThat(finding.getIdentityKey()).isEqualTo("npm/acme-internal-utils");
        assertThat(finding.getLifecycleState().name()).isEqualTo("ACTIVE");

        SBOM sourceSbom = onlyActiveSbomFor(SbomLifecycleStage.SOURCE);
        SBOM buildSbom = onlyActiveSbomFor(SbomLifecycleStage.BUILD);
        assertThat(finding.getBaselineSbomId()).isEqualTo(sourceSbom.getId());
        assertThat(finding.getObservedSbomId()).isEqualTo(buildSbom.getId());
    }

    @Test
    @WithMockUser
    void reUploadingACleanBuildAutoResolvesTheFinding() throws Exception {
        uploadAndAwait("source.cdx.json", null);
        uploadAndAwait("build.cdx.json", null);

        List<LifecycleDriftFinding> before = lifecycleDriftFindingRepository.findAll();
        assertThat(before).hasSize(1);
        UUID findingId = before.get(0).getId();
        assertThat(before.get(0).getLifecycleState().name()).isEqualTo("ACTIVE");

        uploadAndAwait("build-clean.cdx.json", null);

        LifecycleDriftFinding after = lifecycleDriftFindingRepository.findById(findingId).orElseThrow();
        assertThat(after.getLifecycleState().name()).isEqualTo("AUTO_RESOLVED");
        assertThat(lifecycleDriftFindingRepository.findAll()).hasSize(1);
    }

    @Test
    @WithMockUser
    void oneSbomPerStageIngestsCleanlyIntoOneDeduplicatedInventory() throws Exception {
        uploadAndAwait("source.cdx.json", null);
        uploadAndAwait("build-clean.cdx.json", null);
        uploadAndAwait("analyzed.cdx.json", null);
        uploadAndAwait("deployed.spdx.json", "deployed");

        List<SBOM> active = sbomRepository.findAllByProductIdAndActiveTrue(productId);
        assertThat(active).hasSize(4);
        assertThat(active.stream().map(SBOM::getLifecycleStage))
                .containsExactlyInAnyOrder(SbomLifecycleStage.SOURCE, SbomLifecycleStage.BUILD,
                        SbomLifecycleStage.ANALYZED, SbomLifecycleStage.DEPLOYED);

        List<LifecycleDriftFinding> activeFindings = lifecycleDriftFindingRepository.findAll().stream()
                .filter(f -> f.getLifecycleState().name().equals("ACTIVE"))
                .toList();
        assertThat(activeFindings).as("clean, consistent stages must raise nothing").isEmpty();
    }

    /* ---------------------------------------------------------------------- */
    /* Helpers                                                                */
    /* ---------------------------------------------------------------------- */

    private void uploadAndAwait(String fixture, String stage) throws Exception {
        var request = post("/sbom/{productId}/sboms", productId)
                .param("productVersion", "1.0.0")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture));
        if (stage != null) {
            request = request.param("stage", stage);
        }
        String responseBody = mockMvc.perform(request)
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();

        UUID jobId = extractJobId(responseBody);
        jobRunner.poll();
        awaitJobTerminal(jobId);
    }

    private static UUID extractJobId(String responseBody) {
        // Job JSON starts with {"id":"<uuid>", ...}
        int start = responseBody.indexOf("\"id\":\"") + 6;
        int end = responseBody.indexOf('"', start);
        return UUID.fromString(responseBody.substring(start, end));
    }

    private Job awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        Job job = jobRepository.findById(id).orElseThrow();
        assertThat(job.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        return job;
    }

    private SBOM onlyActiveSbomFor(SbomLifecycleStage stage) {
        List<SBOM> matches = sbomRepository.findAllByProductIdAndActiveTrue(productId).stream()
                .filter(s -> s.getLifecycleStage() == stage)
                .toList();
        assertThat(matches).as("exactly one active %s SBOM", stage).hasSize(1);
        return matches.get(0);
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/lifecycle/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
