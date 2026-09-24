package net.jdesive.secy.job;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.AsyncConfig;
import net.jdesive.secy.events.FeedIngestedEvent;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.AssetScanIngestJobService;
import net.jdesive.secy.service.ComplianceScanIngestJobService;
import net.jdesive.secy.service.ConnectorSyncService;
import net.jdesive.secy.service.CveListIngestService;
import net.jdesive.secy.service.EPSSService;
import net.jdesive.secy.service.ExploitIndexService;
import net.jdesive.secy.service.KEVService;
import net.jdesive.secy.service.MaliciousPackageIngestService;
import net.jdesive.secy.service.MalwareHashIngestService;
import net.jdesive.secy.service.NVDService;
import net.jdesive.secy.service.OsvIngestService;
import net.jdesive.secy.service.SbomIngestJobService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

/**
 * Claims queued ingestion jobs and runs them on the dedicated worker pool.
 *
 * <p><b>Why a poller and not a plain {@code @Async} dispatch from the controller.</b> An
 * {@code @Async} hand-off only exists in the heap of the JVM that took the request: kill the app
 * between the {@code 202} and the ingest finishing and the job is gone, with a {@code QUEUED} row
 * left behind that nothing will ever pick up. Polling makes the database the queue — the row *is*
 * the work item, so a restart resumes the backlog, and the claim is a guarded
 * {@code QUEUED -> RUNNING} transition under an optimistic lock, which means a second app instance
 * can be added later without two of them running the same feed pull. The cost is up to one poll
 * interval of latency before a job starts, which is nothing next to a multi-minute NVD pull.
 *
 * <p>{@link JobScheduler} owns the timer; this class is directly callable so tests can drive it
 * without waiting on the clock.
 */
@Slf4j
@Component
public class JobRunner {

    /** Don't write a progress row more often than this; feed batches can land in quick succession. */
    private static final long PROGRESS_FLUSH_INTERVAL_MS = 2_000;

    private final JobService jobService;

    private final KEVService kevService;

    private final EPSSService epssService;

    private final NVDService nvdService;

    private final ExploitIndexService exploitIndexService;

    private final AsyncTaskExecutor executor;

    private final IngestionJobProperties properties;

    private final ApplicationEventPublisher events;

    private final OsvIngestService osvIngestService;

    private final CveListIngestService cveListIngestService;

    private final SbomIngestJobService sbomIngestJobService;

    private final AssetScanIngestJobService assetScanIngestJobService;

    private final ComplianceScanIngestJobService complianceScanIngestJobService;

    private final MaliciousPackageIngestService maliciousPackageIngestService;

    private final MalwareHashIngestService malwareHashIngestService;

    private final ConnectorSyncService connectorSyncService;

    /**
     * Jobs this instance has dispatched and not yet finished, each mapped to its worker thread's
     * {@link Future} — a local capacity guard (correctness of the claim itself rests on the
     * database transition, not on this map) that doubles as the reaper's way to actually stop a
     * worker: see {@link #cancel(UUID)}. A placeholder value reserves the slot between the guard
     * check and the real {@code submit()} call so two overlapping {@link #poll()} calls can never
     * both dispatch the same job.
     */
    private final Map<UUID, Future<?>> running = new ConcurrentHashMap<>();

    private static final Future<?> RESERVED = CompletableFuture.completedFuture(null);

    @Autowired
    public JobRunner(JobService jobService,
                     KEVService kevService,
                     EPSSService epssService,
                     NVDService nvdService,
                     ExploitIndexService exploitIndexService,
                     @Qualifier(AsyncConfig.INGESTION_EXECUTOR) AsyncTaskExecutor executor,
                     IngestionJobProperties properties,
                     ApplicationEventPublisher events,
                     OsvIngestService osvIngestService,
                     CveListIngestService cveListIngestService,
                     SbomIngestJobService sbomIngestJobService,
                     AssetScanIngestJobService assetScanIngestJobService,
                     ComplianceScanIngestJobService complianceScanIngestJobService,
                     MaliciousPackageIngestService maliciousPackageIngestService,
                     MalwareHashIngestService malwareHashIngestService,
                     ConnectorSyncService connectorSyncService) {
        this.jobService = jobService;
        this.kevService = kevService;
        this.epssService = epssService;
        this.nvdService = nvdService;
        this.exploitIndexService = exploitIndexService;
        this.executor = executor;
        this.properties = properties;
        this.events = events;
        this.osvIngestService = osvIngestService;
        this.cveListIngestService = cveListIngestService;
        this.sbomIngestJobService = sbomIngestJobService;
        this.assetScanIngestJobService = assetScanIngestJobService;
        this.complianceScanIngestJobService = complianceScanIngestJobService;
        this.maliciousPackageIngestService = maliciousPackageIngestService;
        this.malwareHashIngestService = malwareHashIngestService;
        this.connectorSyncService = connectorSyncService;
    }

    /**
     * Claim and dispatch up to the pool's remaining capacity, oldest job first.
     *
     * @return how many jobs were handed to the worker pool
     */
    public int poll() {
        int capacity = properties.getWorkerPoolSize() - running.size();
        if (capacity <= 0) {
            return 0;
        }

        List<Job> queued = jobService.findQueued();
        int dispatched = 0;

        for (Job candidate : queued) {
            if (dispatched >= capacity) {
                break;
            }
            UUID id = candidate.getId();
            if (running.putIfAbsent(id, RESERVED) != null) {
                continue;
            }

            Job claimed = jobService.claim(id).orElse(null);
            if (claimed == null) {
                running.remove(id);
                continue;
            }

            dispatched++;
            try {
                Future<?> future = executor.submit(() -> {
                    try {
                        execute(claimed.getId(), claimed.getType());
                    } finally {
                        running.remove(id);
                    }
                });
                running.put(id, future);
            } catch (RejectedExecutionException e) {
                running.remove(id);
                log.warn("Ingestion pool rejected job {}", id, e);
                jobService.finish(id, JobStatus.FAILED, 0, "Ingestion worker pool is saturated; try again shortly.");
            }
        }

        return dispatched;
    }

    /**
     * Interrupt a job's worker thread — called once the reaper has failed its database row, so a
     * job that turned out not to be stalled (just slow) does not keep running invisibly under a
     * row that now says {@code FAILED}, and so its feed's active slot is genuinely free for a new
     * enqueue rather than racing a zombie. A no-op if this instance is not the one running it
     * (already finished, or claimed by a different process entirely).
     */
    public void cancel(UUID id) {
        Future<?> future = running.get(id);
        if (future != null) {
            future.cancel(true);
        }
    }

    /**
     * Run one already-claimed job to a terminal state. Runs on a worker thread and deliberately
     * holds no transaction — a feed pull takes minutes.
     */
    void execute(UUID id, JobType type) {
        log.info("Running {} ingestion job {}", type, id);
        DatabaseJobProgress progress = new DatabaseJobProgress(id);
        try {
            IngestResult result = dispatch(id, type, progress);
            jobService.finish(id, JobStatus.SUCCEEDED, result.itemsProcessed(), result.message());
            log.info("{} ingestion job {} succeeded: {}", type, id, result.message());
            // Downstream consequences of a feed changing (re-running the actionable funnel over
            // existing alerts) hang off this event rather than another job row. See
            // ReEnrichmentListener.
            events.publishEvent(new FeedIngestedEvent(id, type));
        } catch (CancellationException e) {
            Thread.currentThread().interrupt();
            jobService.finish(id, JobStatus.CANCELLED, progress.itemsProcessed, "Cancelled before completion.");
            log.warn("{} ingestion job {} cancelled", type, id);
        } catch (Exception e) {
            jobService.finish(id, JobStatus.FAILED, progress.itemsProcessed, describe(e));
            log.error("{} ingestion job {} failed", type, id, e);
        }
    }

    private IngestResult dispatch(UUID id, JobType type, JobProgress progress) {
        return switch (type) {
            case KEV -> kevService.ingest(progress);
            case EPSS -> epssService.ingestEPSSData(progress);
            case NVD -> nvdService.ingestData(progress);
            case EXPLOIT -> exploitIndexService.ingest(progress);
            case OSV -> osvIngestService.ingest(progress);
            case CVE_LIST -> cveListIngestService.ingest(progress);
            // Phase 6's two threat feeds. Singleton pulls like the rest of this block; the
            // compromise findings they enable are raised by CompromiseDetectionService on the next
            // SBOM upload or asset scan, not here.
            case MALICIOUS_PACKAGES -> maliciousPackageIngestService.ingest(progress);
            case MALWARE_HASHES -> malwareHashIngestService.ingest(progress);
            // The types carrying per-invocation data — dispatch needs the job's own id to look up
            // which SBOM, asset or compliance report it is for. See SBOMService.ingestUploadJob /
            // SBOM.jobId, AssetService.ingestScanJob / Asset.jobId and
            // ComplianceService.ingestScanJob / DockerComplianceReport.jobId.
            case SBOM_UPLOAD -> sbomIngestJobService.ingest(id, progress);
            case ASSET_SCAN -> assetScanIngestJobService.ingest(id, progress);
            case COMPLIANCE_SCAN -> complianceScanIngestJobService.ingest(id, progress);
            // Looks up which SourceConnector by job id, same as the three above — see
            // SourceConnectorService.beginSyncJob / SourceConnector.jobId.
            case CONNECTOR_SYNC -> connectorSyncService.ingest(id, progress);
        };
    }

    /** Exception message for the job row, falling back to the class name when there is none. */
    private static String describe(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = root.getMessage();
        if (message == null || message.isBlank()) {
            return root.getClass().getSimpleName();
        }
        return root.getClass().getSimpleName() + ": " + message;
    }

    /**
     * Writes progress onto the job row, rate-limited so a chatty feed does not turn into one UPDATE
     * per batch. The first report always lands, so the UI sees movement quickly.
     */
    private final class DatabaseJobProgress implements JobProgress {

        private final UUID jobId;

        private volatile int itemsProcessed;

        private long lastFlushedAt;

        private DatabaseJobProgress(UUID jobId) {
            this.jobId = jobId;
        }

        @Override
        public void report(int itemsProcessed, String message) {
            this.itemsProcessed = itemsProcessed;
            long now = System.currentTimeMillis();
            if (lastFlushedAt != 0 && now - lastFlushedAt < PROGRESS_FLUSH_INTERVAL_MS) {
                return;
            }
            lastFlushedAt = now;
            jobService.progress(jobId, itemsProcessed, message);
        }

    }

}
