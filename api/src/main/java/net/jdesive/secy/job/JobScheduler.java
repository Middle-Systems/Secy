package net.jdesive.secy.job;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The two timers behind the ingestion queue, kept apart from the logic they trigger so tests can
 * drive {@link JobRunner} and {@link JobService} directly instead of waiting on a clock.
 *
 * <p>The placeholders repeat the defaults from {@link IngestionJobProperties} because the test
 * profile replaces {@code application.properties} wholesale, so {@code secy.jobs.*} is absent there.
 *
 * <p>{@code secy.jobs.scheduler-enabled=false} switches both timers off. The test profile does
 * exactly that: every {@code @SpringBootTest} context in the suite shares one in-memory H2
 * database, so a live poller in a cached context happily claims and runs jobs another test class
 * had just written — which is both non-deterministic and not what that test was asking for.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "secy.jobs.scheduler-enabled", havingValue = "true", matchIfMissing = true)
public class JobScheduler {

    private final JobRunner jobRunner;

    private final JobService jobService;

    private final IngestionJobProperties properties;

    @Autowired
    public JobScheduler(JobRunner jobRunner, JobService jobService, IngestionJobProperties properties) {
        this.jobRunner = jobRunner;
        this.jobService = jobService;
        this.properties = properties;
    }

    /**
     * Pick up queued jobs — including any left behind by a restart, which is the whole reason the
     * queue is polled from the database rather than dispatched in-process.
     */
    @Scheduled(fixedDelayString = "${secy.jobs.poll-interval:PT10S}", initialDelayString = "${secy.jobs.poll-interval:PT10S}")
    public void pollQueue() {
        try {
            int dispatched = jobRunner.poll();
            if (dispatched > 0) {
                log.debug("Dispatched {} ingestion job(s)", dispatched);
            }
        } catch (Exception e) {
            // Never let a bad tick kill the schedule.
            log.error("Ingestion queue poll failed", e);
        }
    }

    /**
     * Fail jobs stuck in {@code RUNNING} — a worker that died, or an app killed mid-ingest, would
     * otherwise hold that feed's active slot forever and block every later enqueue.
     */
    @Scheduled(fixedDelayString = "${secy.jobs.stale-timeout:PT30M}", initialDelayString = "${secy.jobs.stale-timeout:PT30M}")
    public void reapStaleJobs() {
        try {
            int reaped = jobService.reapStale(properties.getStaleTimeout());
            if (reaped > 0) {
                log.warn("Reaped {} stalled ingestion job(s)", reaped);
            }
        } catch (Exception e) {
            log.error("Stale ingestion job reaper failed", e);
        }
    }

}
