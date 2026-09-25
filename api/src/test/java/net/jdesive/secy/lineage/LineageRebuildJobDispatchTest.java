package net.jdesive.secy.lineage;

import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
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
 * {@link JobType#LINEAGE_REBUILD} dispatch through {@link JobRunner}, and its HTTP surface
 * ({@code POST /lineage/rebuild}). Mirrors {@code CveListJobDispatchTest}'s pattern — the actual
 * rebuild logic, with the writer stubbed/faked, lives in {@code LineageRebuildServiceTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LineageRebuildJobDispatchTest {

    private static final Duration SETTLE = Duration.ofSeconds(10);

    @MockBean
    private LineageRebuildService lineageRebuildService;

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
    void theRunnerDispatchesALineageRebuildJobToItsService() {
        when(lineageRebuildService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(1, "Rebuilt lineage graph for 1 tenant(s): 4 nodes, 3 edges"));

        Job queued = jobService.enqueue(JobType.LINEAGE_REBUILD, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getType()).isEqualTo(JobType.LINEAGE_REBUILD);
        assertThat(finished.getItemsProcessed()).isEqualTo(1);
        assertThat(finished.getMessage()).contains("nodes");
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void postLineageRebuildAnswers202WithAQueuedJobWhenAvailable() throws Exception {
        when(lineageRebuildService.isAvailable()).thenReturn(true);

        mockMvc.perform(post("/lineage/rebuild"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("LINEAGE_REBUILD"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"));
    }

    @Test
    @WithMockUser
    void postLineageRebuildAnswers503WhenNotAvailable() throws Exception {
        when(lineageRebuildService.isAvailable()).thenReturn(false);

        mockMvc.perform(post("/lineage/rebuild"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void postLineageRebuildRequiresAuthentication() throws Exception {
        mockMvc.perform(post("/lineage/rebuild")).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void theRebuildEndpointDoesNotAnswerGet() throws Exception {
        mockMvc.perform(get("/lineage/rebuild")).andExpect(status().isMethodNotAllowed());
    }

    private Job awaitTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> reload(id).getStatus().isTerminal());
        return reload(id);
    }

    private Job reload(UUID id) {
        return jobRepository.findById(id).orElseThrow();
    }

}
