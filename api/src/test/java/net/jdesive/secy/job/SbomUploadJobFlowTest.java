package net.jdesive.secy.job;

import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.service.SbomIngestJobService;
import org.junit.jupiter.api.Assertions;
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
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code SBOM_UPLOAD} job end to end, on the offline H2 profile: {@code POST} answers
 * {@code 202} with a {@code QUEUED} job carrying nothing but a placeholder {@code SBOM} id;
 * {@link JobRunner#poll()} claims and runs it; the components land, the (real) async vulnerability
 * scan that follows runs to completion, and the SBOM's status reflects that.
 *
 * <p>Deliberately not {@code @Transactional}, unlike {@code SbomUploadFormatTest} — the whole point
 * here is for the upload's placeholder-creation transaction, the job's ingest transaction and the
 * scan's transaction to each actually commit, since {@link JobRunner} and {@code
 * VulnerabilityScanner} run on their own worker threads and need something to observe.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomUploadJobFlowTest {

    /** Generous: two async hops (the job runner, then the scan) on a shared CI box. */
    private static final Duration SETTLE = Duration.ofSeconds(15);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private net.jdesive.secy.persistence.JobRepository jobRepository;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private SbomIngestJobService sbomIngestJobService;

    private UUID productId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        alertRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("sbom-upload-flow-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void aValidUploadIsQueuedRunToSuccessAndItsComponentsArePersisted() throws Exception {
        String responseBody = upload(productId, "cyclonedx-mixed.json")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("SBOM_UPLOAD"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"))
                .andReturn().getResponse().getContentAsString();

        // The controller's own synchronous half: a placeholder row exists immediately, with nothing
        // ingested into it yet.
        SBOM placeholder = onlySbomWithComponents();
        assertThat(placeholder.getStatus()).isEqualTo("QUEUED");
        assertThat(placeholder.isActive()).isTrue();
        assertThat(placeholder.getComponents()).isEmpty();

        UUID jobId = jobRepository.findAll().get(0).getId();
        assertThat(responseBody).contains(jobId.toString());

        jobRunner.poll();

        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        // cyclonedx-mixed.json declares 3 dependency components (the root/metadata component is
        // held separately and does not count).
        assertThat(finished.getItemsProcessed()).isEqualTo(3);
        assertThat(finished.getMessage()).contains("CycloneDX");

        // The job's ingest transaction publishes SbomUploadedEvent on commit, which kicks off
        // VulnerabilityScanner's async scan on a *different* pool — wait for that hop too before
        // calling the SBOM done, exactly as a real client polling GET /products would have to.
        SBOM scanned = awaitSbomStatus(placeholder.getId(), "COMPLETED", "FAILED");
        assertThat(scanned.getStatus())
                .as("no CVE/OSV data is loaded in this test, so correlation runs and finds nothing — "
                        + "not an error")
                .isEqualTo("COMPLETED");
        // 3 dependencies plus the root/metadata component ("acme-web") — pre-existing behaviour
        // unchanged by Phase 3: SBOM.components is mappedBy sbom_component.sbom_id, and toEntity()
        // sets that FK on the root component too (only sbom.component points at it specifically),
        // so a DB-driven re-fetch of the collection includes it. This test pins the shape as it
        // already was, not a new effect of moving ingest onto the job queue.
        assertThat(scanned.getComponents()).hasSize(4);
        assertThat(scanned.getComponent()).isNotNull();
        assertThat(scanned.getComponent().getName()).isEqualTo("acme-web");
        assertThat(scanned.getPendingRawBody()).as("consumed once ingested").isNull();
        assertThat(scanned.getLastScannedAt()).isNotNull();
    }

    @Test
    @WithMockUser
    void concurrentUploadsForDifferentProductsEachGetTheirOwnJobRatherThanSharingOne() throws Exception {
        Product other = new Product();
        other.setName("sbom-upload-flow-other-" + UUID.randomUUID());
        UUID otherProductId = productRepository.save(other).getId();

        upload(productId, "cyclonedx-mixed.json").andExpect(status().isAccepted());
        upload(otherProductId, "spdx-2.2-minimal.json").andExpect(status().isAccepted());

        // Unlike a feed's "one active job per type" (KEV/EPSS/NVD/...), SBOM_UPLOAD jobs never
        // collapse onto each other: each upload is its own unit of work with its own payload.
        assertThat(jobRepository.count()).isEqualTo(2);
        assertThat(sbomRepository.count()).isEqualTo(2);
    }

    @Test
    void aJobThatFailsMidIngestLeavesTheSbomRowFailedNotStuck() {
        // Bypasses the controller (which would have already rejected an unparseable body with 400)
        // to exercise the job-side failure path directly: a placeholder row whose stashed body is
        // corrupt, as if it had been damaged between the controller writing it and the job reading
        // it back.
        UUID jobId = UUID.randomUUID();
        SBOM placeholder = new SBOM();
        placeholder.setProduct(productRepository.findById(productId).orElseThrow());
        placeholder.setFormat("CycloneDX");
        placeholder.setSpecVersion("1.5");
        placeholder.setVersion(1);
        placeholder.setActive(true);
        placeholder.setStatus("QUEUED");
        placeholder.setUploadDate(java.time.LocalDateTime.now());
        placeholder.setPendingRawBody("{ this is not valid json");
        placeholder.setJobId(jobId);
        UUID sbomId = sbomRepository.saveAndFlush(placeholder).getId();

        Assertions.assertThrows(RuntimeException.class, () -> sbomIngestJobService.ingest(jobId, JobProgress.NOOP));

        SBOM reloaded = sbomRepository.findById(sbomId).orElseThrow();
        assertThat(reloaded.getStatus())
                .as("the UI must never show a permanently-stuck PROCESSING/QUEUED row")
                .isEqualTo("FAILED");
        assertThat(reloaded.getPendingRawBody()).isNull();
    }

    /* ---------------------------------------------------------------------- */
    /* Helpers                                                                */
    /* ---------------------------------------------------------------------- */

    private org.springframework.test.web.servlet.ResultActions upload(UUID product, String fixture) throws Exception {
        return mockMvc.perform(post("/sbom/{productId}/sboms", product)
                .param("productVersion", "1.0.0")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture)));
    }

    /** {@code components} is lazy and this test has no open session at assertion time — fetch it. */
    private SBOM onlySbomWithComponents() {
        var all = sbomRepository.findAll();
        assertThat(all).hasSize(1);
        return sbomRepository.findByIdWithComponents(all.get(0).getId()).orElseThrow();
    }

    private Job awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        return jobRepository.findById(id).orElseThrow();
    }

    private SBOM awaitSbomStatus(UUID id, String... terminalStatuses) {
        Set<String> terminal = Set.of(terminalStatuses);
        await().atMost(SETTLE).until(() -> terminal.contains(sbomRepository.findById(id).orElseThrow().getStatus()));
        return sbomRepository.findByIdWithComponents(id).orElseThrow();
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
