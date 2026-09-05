package net.jdesive.secy.job;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.AsyncConfig;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.EPSSService;
import net.jdesive.secy.service.KEVService;
import net.jdesive.secy.service.NVDService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
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

    private final Executor executor;

    private final IngestionJobProperties properties;

    /**
     * Jobs this instance has dispatched and not yet finished. Purely a local capacity guard so the
     * poller does not submit more work than the pool can hold — correctness of the claim itself
     * rests on the database transition, not on this set.
     */
    private final Set<UUID> inFlight = ConcurrentHashMap.newKeySet();

    @Autowired
    public JobRunner(JobService jobService,
                     KEVService kevService,
                     EPSSService epssService,
                     NVDService nvdService,
                     @Qualifier(AsyncConfig.INGESTION_EXECUTOR) Executor executor,
                     IngestionJobProperties properties) {
        this.jobService = jobService;
        this.kevService = kevService;
        this.epssService = epssService;
        this.nvdService = nvdService;
        this.executor = executor;
        this.properties = properties;
    }

    /**
     * Claim and dispatch up to the pool's remaining capacity, oldest job first.
     *
     * @return how many jobs were handed to the worker pool
     */
    public int poll() {
        int capacity = properties.getWorkerPoolSize() - inFlight.size();
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
            if (!inFlight.add(id)) {
                continue;
            }

            Job claimed = jobService.claim(id).orElse(null);
            if (claimed == null) {
                inFlight.remove(id);
                continue;
            }

            dispatched++;
            try {
                executor.execute(() -> {
                    try {
                        execute(claimed.getId(), claimed.getType());
                    } finally {
                        inFlight.remove(id);
                    }
                });
            } catch (RejectedExecutionException e) {
                inFlight.remove(id);
                log.warn("Ingestion pool rejected job {}", id, e);
                jobService.finish(id, JobStatus.FAILED, 0, "Ingestion worker pool is saturated; try again shortly.");
            }
        }

        return dispatched;
    }

    /**
     * Run one already-claimed job to a terminal state. Runs on a worker thread and deliberately
     * holds no transaction — a feed pull takes minutes.
     */
    void execute(UUID id, JobType type) {
        log.info("Running {} ingestion job {}", type, id);
        DatabaseJobProgress progress = new DatabaseJobProgress(id);
        try {
            IngestResult result = dispatch(type, progress);
            jobService.finish(id, JobStatus.SUCCEEDED, result.itemsProcessed(), result.message());
            log.info("{} ingestion job {} succeeded: {}", type, id, result.message());
        } catch (CancellationException e) {
            Thread.currentThread().interrupt();
            jobService.finish(id, JobStatus.CANCELLED, progress.itemsProcessed, "Cancelled before completion.");
            log.warn("{} ingestion job {} cancelled", type, id);
        } catch (Exception e) {
            jobService.finish(id, JobStatus.FAILED, progress.itemsProcessed, describe(e));
            log.error("{} ingestion job {} failed", type, id, e);
        }
    }

    private IngestResult dispatch(JobType type, JobProgress progress) {
        return switch (type) {
            case KEV -> kevService.ingest(progress);
            case EPSS -> epssService.ingestEPSSData(progress);
            case NVD -> nvdService.ingestData(progress);
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
