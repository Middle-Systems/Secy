package net.jdesive.secy.job;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.EPSSService;
import net.jdesive.secy.service.ExploitIndexService;
import net.jdesive.secy.service.KEVService;
import net.jdesive.secy.service.NVDService;
import net.jdesive.secy.service.MaliciousPackageIngestService;
import net.jdesive.secy.service.MalwareHashIngestService;
import net.jdesive.secy.service.CompromiseAgingService;
import net.jdesive.secy.service.OsvIngestService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestClientException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end behaviour of the ingestion queue, on the offline H2 profile.
 *
 * <p>The three feed services are mocked, so nothing here reaches cisa.gov, first.org or
 * nvd.nist.gov — see {@code KEVServiceIngestTest} for the ingest itself, which stubs the HTTP
 * transport instead.
 */
@SpringBootTest
@AutoConfigureMockMvc
class IngestionJobFlowTest {

    /** Generous — the runner only has to bounce a mock through the worker pool. */
    private static final Duration SETTLE = Duration.ofSeconds(10);

    @MockBean
    private KEVService kevService;

    @MockBean
    private EPSSService epssService;

    @MockBean
    private NVDService nvdService;

    @MockBean
    private ExploitIndexService exploitIndexService;

    @MockBean
    private OsvIngestService osvIngestService;

    @MockBean
    private MaliciousPackageIngestService maliciousPackageIngestService;

    @MockBean
    private MalwareHashIngestService malwareHashIngestService;

    @Autowired
    private JobService jobService;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private IngestionJobProperties jobProperties;

    @Autowired
    private CompromiseAgingService compromiseAgingService;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void clearQueue() {
        jobRepository.deleteAll();
    }

    /* ---------------------------------------------------------------------- */
    /* Enqueue                                                                */
    /* ---------------------------------------------------------------------- */

    @Test
    void enqueueCreatesAQueuedJob() {
        Job job = jobService.enqueue(JobType.KEV, "alice@example.com");

        assertThat(job.getId()).isNotNull();
        assertThat(job.getStatus()).isEqualTo(JobStatus.QUEUED);
        assertThat(job.getType()).isEqualTo(JobType.KEV);
        assertThat(job.getCreatedAt()).isNotNull();
        assertThat(job.getStartedAt()).isNull();
        assertThat(job.getFinishedAt()).isNull();
        assertThat(job.getItemsProcessed()).isZero();
        assertThat(job.getTriggeredBy()).isEqualTo("alice@example.com");
    }

    @Test
    void enqueueWithoutAPrincipalIsAttributedToTheSystem() {
        assertThat(jobService.enqueue(JobType.EPSS, (String) null).getTriggeredBy()).isEqualTo("system");
    }

    @Test
    void aSecondEnqueueOfAnActiveTypeReturnsTheSameJob() {
        Job first = jobService.enqueue(JobType.NVD, "alice@example.com");
        Job second = jobService.enqueue(JobType.NVD, "bob@example.com");

        assertThat(second.getId()).isEqualTo(first.getId());
        assertThat(second.getTriggeredBy()).isEqualTo("alice@example.com");
        assertThat(jobRepository.count()).isEqualTo(1);
    }

    @Test
    void aTypeCanBeQueuedAgainOnceTheLastRunFinished() {
        Job first = jobService.enqueue(JobType.KEV, "alice@example.com");
        jobService.finish(first.getId(), JobStatus.SUCCEEDED, 3, "done");

        Job second = jobService.enqueue(JobType.KEV, "alice@example.com");

        assertThat(second.getId()).isNotEqualTo(first.getId());
        assertThat(second.getStatus()).isEqualTo(JobStatus.QUEUED);
    }

    /* ---------------------------------------------------------------------- */
    /* Running                                                                */
    /* ---------------------------------------------------------------------- */

    @Test
    void theRunnerDrivesAQueuedJobToSucceeded() {
        when(kevService.ingest(any(JobProgress.class))).thenReturn(new IngestResult(42, "42 KEV entries ingested"));

        Job queued = jobService.enqueue(JobType.KEV, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getItemsProcessed()).isEqualTo(42);
        assertThat(finished.getMessage()).isEqualTo("42 KEV entries ingested");
        assertThat(finished.getStartedAt()).isNotNull();
        assertThat(finished.getFinishedAt()).isNotNull();
    }

    @Test
    void theRunnerDispatchesAnExploitIndexJobToItsService() {
        when(exploitIndexService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(7, "7 CVEs with a public exploit (metasploit source unavailable)"));

        Job queued = jobService.enqueue(JobType.EXPLOIT, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getType()).isEqualTo(JobType.EXPLOIT);
        assertThat(finished.getItemsProcessed()).isEqualTo(7);
        assertThat(finished.getMessage()).contains("metasploit source unavailable");
    }

    @Test
    void theRunnerDispatchesAnOsvJobToItsService() {
        when(osvIngestService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(123, "Ingested 123 OSV records across 1 ecosystem(s): npm (123)"));

        Job queued = jobService.enqueue(JobType.OSV, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getType()).isEqualTo(JobType.OSV);
        assertThat(finished.getItemsProcessed()).isEqualTo(123);
        assertThat(finished.getMessage()).contains("npm (123)");
    }

    @Test
    void theRunnerDispatchesTheTwoPhase6ThreatFeedsToTheirOwnServices() {
        when(maliciousPackageIngestService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(4200, "Ingested 4200 malicious-package rows from 4100 record(s)"));
        when(malwareHashIngestService.ingest(any(JobProgress.class)))
                .thenReturn(new IngestResult(876, "Ingested 876 MalwareBazaar sample(s) (public CSV export, no Auth-Key)"));

        // Also the regression guard for migration 011e: ingestion_job.type was varchar(16) and
        // 'MALICIOUS_PACKAGES' is 18 characters. Every enum name up to COMPLIANCE_SCAN (15) fitted,
        // so nothing before this would have caught the overflow.
        Job packages = jobService.enqueue(JobType.MALICIOUS_PACKAGES, "alice@example.com");
        Job hashes = jobService.enqueue(JobType.MALWARE_HASHES, "alice@example.com");
        jobRunner.poll();

        Job finishedPackages = awaitTerminal(packages.getId());
        assertThat(finishedPackages.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finishedPackages.getType()).isEqualTo(JobType.MALICIOUS_PACKAGES);
        assertThat(finishedPackages.getItemsProcessed()).isEqualTo(4200);

        Job finishedHashes = awaitTerminal(hashes.getId());
        assertThat(finishedHashes.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finishedHashes.getType()).isEqualTo(JobType.MALWARE_HASHES);
        assertThat(finishedHashes.getItemsProcessed()).isEqualTo(876);
    }

    @Test
    void theTwoThreatFeedsHoldSeparateActiveSlotsSoNeitherBlocksTheOther() {
        // The reason they are two JobTypes and not one shared THREAT type: the
        // uq_ingestion_job_active_type constraint is per type, so sharing would let a multi-minute
        // 310 MB malicious-packages pull block a one-second hash refresh.
        Job packages = jobService.enqueue(JobType.MALICIOUS_PACKAGES, "alice@example.com");
        Job hashes = jobService.enqueue(JobType.MALWARE_HASHES, "alice@example.com");

        assertThat(hashes.getId()).isNotEqualTo(packages.getId());
        assertThat(jobRepository.findAll()).hasSize(2);

        // But a second enqueue of the SAME type still returns the in-flight job — these are
        // singleton feed pulls, unlike SBOM_UPLOAD / ASSET_SCAN / COMPLIANCE_SCAN.
        assertThat(jobService.enqueue(JobType.MALICIOUS_PACKAGES, "bob@example.com").getId())
                .isEqualTo(packages.getId());
    }

    @Test
    void theRunnerFailsTheJobAndKeepsTheErrorMessage() {
        when(epssService.ingestEPSSData(any(JobProgress.class)))
                .thenThrow(new RestClientException("api.first.org is unreachable"));

        Job queued = jobService.enqueue(JobType.EPSS, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.FAILED);
        assertThat(finished.getMessage()).contains("api.first.org is unreachable");
        assertThat(finished.getFinishedAt()).isNotNull();
    }

    @Test
    void progressIsVisibleOnTheJobRowWhileTheIngestRuns() {
        when(nvdService.ingestData(any(JobProgress.class))).thenAnswer(invocation -> {
            JobProgress progress = invocation.getArgument(0);
            progress.report(1_000, "Ingested 1000 of 4000 CVE records…");

            // Still mid-ingest: the count must already be readable through the job row. A failure
            // here throws on the worker thread, which shows up as the job ending FAILED below.
            Job midRun = reload(currentNvdJobId());
            assertThat(midRun.getStatus()).isEqualTo(JobStatus.RUNNING);
            assertThat(midRun.getItemsProcessed()).isEqualTo(1_000);
            assertThat(midRun.getMessage()).isEqualTo("Ingested 1000 of 4000 CVE records…");

            return new IngestResult(4_000, "4000 CVE records ingested");
        });

        Job queued = jobService.enqueue(JobType.NVD, "alice@example.com");
        jobRunner.poll();

        Job finished = awaitTerminal(queued.getId());
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getItemsProcessed()).isEqualTo(4_000);
    }

    /* ---------------------------------------------------------------------- */
    /* Terminal states and the reaper                                         */
    /* ---------------------------------------------------------------------- */

    @Test
    void aTerminalJobIsNeverMovedAgain() {
        Job job = jobService.enqueue(JobType.KEV, "alice@example.com");
        jobService.claim(job.getId());
        jobService.finish(job.getId(), JobStatus.SUCCEEDED, 7, "7 KEV entries ingested");

        // A worker coming back from the dead, and a late progress report, both bounce off.
        jobService.finish(job.getId(), JobStatus.FAILED, 0, "too late");
        jobService.progress(job.getId(), 999, "even later");

        Job reloaded = reload(job.getId());
        assertThat(reloaded.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(reloaded.getItemsProcessed()).isEqualTo(7);
        assertThat(reloaded.getMessage()).isEqualTo("7 KEV entries ingested");
    }

    @Test
    void aClaimedJobCannotBeClaimedTwice() {
        Job job = jobService.enqueue(JobType.KEV, "alice@example.com");

        assertThat(jobService.claim(job.getId())).isPresent();
        assertThat(jobService.claim(job.getId())).isEmpty();
    }

    @Test
    void theReaperFailsAJobWithNoProgressInAWhile() {
        Job stalled = jobService.enqueue(JobType.NVD, "alice@example.com");
        jobService.claim(stalled.getId());
        backdateProgress(stalled.getId(), LocalDateTime.now().minusHours(2));

        assertThat(jobService.reapStale(Duration.ofMinutes(30))).hasSize(1).containsExactly(stalled.getId());

        Job reaped = reload(stalled.getId());
        assertThat(reaped.getStatus()).isEqualTo(JobStatus.FAILED);
        assertThat(reaped.getMessage()).contains("presumed dead");
        assertThat(reaped.getFinishedAt()).isNotNull();
    }

    @Test
    void theReaperLeavesFinishedAndFreshJobsAlone() {
        Job done = jobService.enqueue(JobType.KEV, "alice@example.com");
        jobService.claim(done.getId());
        backdateProgress(done.getId(), LocalDateTime.now().minusHours(2));
        jobService.finish(done.getId(), JobStatus.SUCCEEDED, 5, "5 KEV entries ingested");

        Job fresh = jobService.enqueue(JobType.EPSS, "alice@example.com");
        jobService.claim(fresh.getId());

        assertThat(jobService.reapStale(Duration.ofMinutes(30))).isEmpty();
        assertThat(reload(done.getId()).getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(reload(fresh.getId()).getStatus()).isEqualTo(JobStatus.RUNNING);
    }

    @Test
    void theReaperLeavesALongRunningJobAloneIfItIsStillReportingProgress() {
        // What today's stuck ingest actually was: a job whose total RUNNING time exceeds
        // stale-timeout but that is still actively reporting -- a rate-limited full historical
        // crawl, not a dead worker. Only silence since the last report should count as stale.
        Job slowButAlive = jobService.enqueue(JobType.NVD, "alice@example.com");
        jobService.claim(slowButAlive.getId());
        backdateStartOnly(slowButAlive.getId(), LocalDateTime.now().minusHours(2));
        jobService.progress(slowButAlive.getId(), 34_000, "Ingested 34000 CVE records…");

        assertThat(jobService.reapStale(Duration.ofMinutes(30))).isEmpty();
        assertThat(reload(slowButAlive.getId()).getStatus()).isEqualTo(JobStatus.RUNNING);
    }

    @Test
    void theStartupReaperFailsARunningJobRegardlessOfAge() {
        // Orphaned seconds ago, not staleTimeout's 30 minutes ago -- a job this fresh is exactly
        // what the periodic reaper (theReaperLeavesFinishedAndFreshJobsAlone) is right to leave
        // alone, but a freshly-booted JVM cannot have claimed it, so the startup reaper must not
        // wait out that same window before catching it.
        Job orphaned = jobService.enqueue(JobType.NVD, "alice@example.com");
        jobService.claim(orphaned.getId());

        // secy.jobs.scheduler-enabled=false in the test profile keeps JobScheduler out of the
        // context (see its class Javadoc), so build one directly rather than autowiring it.
        new JobScheduler(jobRunner, jobService, jobProperties, compromiseAgingService).reapStaleJobsOnStartup();

        Job reaped = reload(orphaned.getId());
        assertThat(reaped.getStatus()).isEqualTo(JobStatus.FAILED);
        assertThat(reaped.getMessage()).contains("presumed dead");
    }

    /* ---------------------------------------------------------------------- */
    /* HTTP surface                                                           */
    /* ---------------------------------------------------------------------- */

    @Test
    @WithMockUser(username = "alice@example.com")
    void postIngestAnswers202WithAQueuedJobThatIsThenPollable() throws Exception {
        String body = mockMvc.perform(post("/kev/ingest"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.type").value("KEV"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"))
                .andReturn().getResponse().getContentAsString();

        UUID id = jobRepository.findAll().get(0).getId();
        assertThat(body).contains(id.toString());

        mockMvc.perform(get("/jobs/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.type").value("KEV"));
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void postingTheSameIngestTwiceReusesTheActiveJob() throws Exception {
        mockMvc.perform(post("/epss/ingest")).andExpect(status().isAccepted());
        mockMvc.perform(post("/epss/ingest")).andExpect(status().isAccepted());

        assertThat(jobRepository.count()).isEqualTo(1);
    }

    @Test
    @WithMockUser
    void theIngestEndpointsNoLongerAnswerGet() throws Exception {
        mockMvc.perform(get("/kev/ingest")).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(get("/epss/ingest")).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(get("/nvd/ingest")).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(get("/osv/ingest")).andExpect(status().isMethodNotAllowed());
    }

    @Test
    @WithMockUser(username = "alice@example.com")
    void postOsvIngestAnswers202WithAQueuedJob() throws Exception {
        mockMvc.perform(post("/osv/ingest"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("OSV"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"));
    }

    @Test
    @WithMockUser
    void jobsAreListedRecentFirstAndFilterable() throws Exception {
        jobService.enqueue(JobType.KEV, "alice@example.com");
        jobService.enqueue(JobType.EPSS, "alice@example.com");

        mockMvc.perform(get("/jobs").param("page", "0").param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content", hasSize(2)));

        mockMvc.perform(get("/jobs").param("type", "KEV"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].type").value("KEV"));

        mockMvc.perform(get("/jobs").param("status", "QUEUED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    @WithMockUser
    void anUnknownJobIs404() throws Exception {
        mockMvc.perform(get("/jobs/{id}", UUID.randomUUID())).andExpect(status().isNotFound());
    }

    /* ---------------------------------------------------------------------- */
    /* Helpers                                                                */
    /* ---------------------------------------------------------------------- */

    private Job awaitTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> reload(id).getStatus().isTerminal());
        return reload(id);
    }

    private Job reload(UUID id) {
        return jobRepository.findById(id).orElseThrow();
    }

    private UUID currentNvdJobId() {
        return jobService.findActive(JobType.NVD).orElseThrow().getId();
    }

    /** Pretend the job's last heartbeat was long ago, so the reaper considers it stalled. */
    private void backdateProgress(UUID id, LocalDateTime at) {
        Job job = reload(id);
        job.setStartedAt(at);
        job.setLastProgressAt(at);
        jobRepository.save(job);
    }

    /** Pretend the job started long ago but keep its heartbeat fresh — still legitimately running. */
    private void backdateStartOnly(UUID id, LocalDateTime startedAt) {
        Job job = reload(id);
        job.setStartedAt(startedAt);
        jobRepository.save(job);
    }

}
