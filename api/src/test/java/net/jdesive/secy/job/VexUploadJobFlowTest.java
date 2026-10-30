package net.jdesive.secy.job;

import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexDocumentStatus;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.service.vex.VexIngestJobService;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code VEX_UPLOAD} job end to end: {@code POST /vex} answers {@code 202} with a placeholder
 * document, {@link JobRunner#poll()} claims and runs it, and no re-enrichment fires afterwards (VEX
 * changes no funnel input — {@code ReEnrichmentListener} excludes this job type).
 *
 * <p>Deliberately not {@code @Transactional}, same reasoning as {@code SbomUploadJobFlowTest}: the
 * upload's placeholder-creation transaction and the job's ingest transaction must each actually
 * commit for {@link JobRunner} (its own worker thread) to have something to observe.
 */
@SpringBootTest
@AutoConfigureMockMvc
class VexUploadJobFlowTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @Autowired
    private VexIngestJobService vexIngestJobService;

    @BeforeEach
    void seed() {
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        jobRepository.deleteAll();
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void aValidUploadIsQueuedRunToSuccessAndItsStatementsArePersisted() throws Exception {
        String responseBody = mockMvc.perform(post("/vex")
                        .param("origin", "TENANT")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("openvex-tenant-not-affected.json")))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("VEX_UPLOAD"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"))
                .andReturn().getResponse().getContentAsString();

        VexDocument placeholder = onlyDocument();
        assertThat(placeholder.getStatus()).isEqualTo(VexDocumentStatus.QUEUED);
        assertThat(placeholder.isActive()).isFalse();
        assertThat(placeholder.getPendingRawBody()).isNotBlank();

        UUID jobId = jobRepository.findAll().get(0).getId();
        assertThat(responseBody).contains(jobId.toString());

        jobRunner.poll();

        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getItemsProcessed()).isEqualTo(1);

        VexDocument ingested = vexDocumentRepository.findById(placeholder.getId()).orElseThrow();
        assertThat(ingested.getStatus()).isEqualTo(VexDocumentStatus.COMPLETED);
        assertThat(ingested.isActive()).isTrue();
        assertThat(ingested.getStatementCount()).isEqualTo(1);
        assertThat(ingested.getPendingRawBody()).as("consumed once ingested").isNull();
        assertThat(vexStatementRepository.findAllByDocumentIdOrderByOrdinalAsc(ingested.getId(),
                org.springframework.data.domain.PageRequest.of(0, 10)).getTotalElements()).isEqualTo(1);
    }

    @Test
    void aJobThatFailsMidIngestLeavesTheDocumentFailedNotStuck() {
        // Bypasses the controller to exercise the job-side failure path directly, same pattern as
        // SbomUploadJobFlowTest's equivalent test.
        UUID jobId = UUID.randomUUID();
        VexDocument placeholder = new VexDocument();
        placeholder.setTenantId(Tenant.DEFAULT_TENANT_ID);
        placeholder.setFormat(VexDocumentFormat.OPENVEX);
        placeholder.setDocumentKey("sha256:corrupt");
        placeholder.setOrigin(VexOrigin.TENANT);
        placeholder.setStatus(VexDocumentStatus.QUEUED);
        placeholder.setContentSha256("deadbeef");
        placeholder.setActive(false);
        placeholder.setPendingRawBody("{ this is not valid json");
        placeholder.setJobId(jobId);
        UUID documentId = vexDocumentRepository.saveAndFlush(placeholder).getId();

        Assertions.assertThrows(RuntimeException.class, () -> vexIngestJobService.ingest(jobId, JobProgress.NOOP));

        VexDocument reloaded = vexDocumentRepository.findById(documentId).orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(VexDocumentStatus.FAILED);
        assertThat(reloaded.getPendingRawBody()).isNull();
        assertThat(reloaded.isActive()).isFalse();
    }

    private VexDocument onlyDocument() {
        var all = vexDocumentRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private Job awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        return jobRepository.findById(id).orElseThrow();
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("vex/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
