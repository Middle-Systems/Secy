package net.jdesive.secy.job;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.CveListIngestService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link JobType#CVE_LIST} dispatch through {@link JobRunner}, and its HTTP surface
 * ({@code POST /cve-list/ingest}). Mirrors {@code IngestionJobFlowTest}'s OSV dispatch test — the
 * ingest itself, with the transport stubbed, lives in {@code CveListIngestServiceTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CveListJobDispatchTest {

    private static final Duration SETTLE = Duration.ofSeconds(10);

    @MockBean
    private CveListIngestService cveListIngestService;

    @Autowired
    private JobService jobService;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void clearQueue() {
        jobRepository.deleteAll();
    }

    @Test
    void theRunnerDispatchesACveListJobToItsService() {
        when(cveListIngestService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(58, "Updated 58 of 60 CVE List records (2 not yet in NVD, 0 malformed)"));

        Job queued = jobService.enqueue(JobType.CVE_LIST, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getType()).isEqualTo(JobType.CVE_LIST);
        assertThat(finished.getItemsProcessed()).isEqualTo(58);
        assertThat(finished.getMessage()).contains("not yet in NVD");
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void postCveListIngestAnswers202WithAQueuedJob() throws Exception {
        mockMvc.perform(post("/cve-list/ingest"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("CVE_LIST"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"));
    }

    @Test
    @WithMockUser
    void theIngestEndpointDoesNotAnswerGet() throws Exception {
        mockMvc.perform(get("/cve-list/ingest")).andExpect(status().isMethodNotAllowed());
    }

    private Job awaitTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> reload(id).getStatus().isTerminal());
        return reload(id);
    }

    private Job reload(UUID id) {
        return jobRepository.findById(id).orElseThrow();
    }

}
