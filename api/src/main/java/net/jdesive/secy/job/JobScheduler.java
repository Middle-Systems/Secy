package net.jdesive.secy.job;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.service.CompromiseAgingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Every {@code @Scheduled} in the application, kept apart from the logic it triggers so tests can
 * drive {@link JobRunner}, {@link JobService} and {@link CompromiseAgingService} directly instead of
 * waiting on a clock.
 *
 * <p>The placeholders repeat the defaults from {@link IngestionJobProperties} because the test
 * profile replaces {@code application.properties} wholesale, so {@code secy.jobs.*} is absent there.
 *
 * <p>{@code secy.jobs.scheduler-enabled=false} switches every timer here off, the Phase 6 aging
 * sweep included. The test profile does exactly that: every {@code @SpringBootTest} context in the
 * suite shares one in-memory H2 database, so a live poller in a cached context happily claims and
 * runs jobs another test class had just written — which is both non-deterministic and not what that
 * test was asking for. The aging sweep would be worse: a nightly demotion firing mid-test would
 * rewrite another class's fixtures.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "secy.jobs.scheduler-enabled", havingValue = "true", matchIfMissing = true)
public class JobScheduler {

    private final JobRunner jobRunner;

    private final JobService jobService;

    private final IngestionJobProperties properties;

    private final CompromiseAgingService compromiseAgingService;

    @Autowired
    public JobScheduler(JobRunner jobRunner, JobService jobService, IngestionJobProperties properties,
                        CompromiseAgingService compromiseAgingService) {
        this.jobRunner = jobRunner;
        this.jobService = jobService;
        this.properties = properties;
        this.compromiseAgingService = compromiseAgingService;
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
     *
     * <p>The {@code fixedDelayString}/{@code initialDelayString} both reuse {@code stale-timeout}
     * deliberately — see {@link #reapStaleJobsOnStartup}, which exists precisely because that
     * shared value means the FIRST check after a restart does not happen for a full
     * {@code stale-timeout} (default 30 minutes), even when the row it needs to catch has been
     * stale since before this process even started.
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

    /**
     * Run the stale-job reaper once, right after startup, instead of waiting for
     * {@link #reapStaleJobs}'s first scheduled tick.
     *
     * <p>A row can only be {@code RUNNING} in this fresh process's eyes if some earlier process
     * claimed it and then vanished without finishing — this JVM has never dispatched anything yet.
     * There is no "maybe it's still legitimately running" case to protect against the way there is
     * mid-uptime, so there is no reason to wait out a full {@code stale-timeout} window before the
     * first look: a job left {@code RUNNING} by a killed process (a crash, an operator killing the
     * backend, a container restart) is caught on the very next tick after the app comes back up,
     * not up to {@code stale-timeout} later on top of however long it had already been stuck.
     * {@link #reapStaleJobs}'s own periodic schedule is unchanged and still the one that catches a
     * job that goes stale <em>during</em> this process's uptime.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void reapStaleJobsOnStartup() {
        try {
            // Duration.ZERO, not staleTimeout: a job's age is irrelevant here. Any RUNNING row is
            // guaranteed orphaned regardless of how recently it started, since this JVM has claimed
            // nothing yet -- unlike reapStaleJobs's periodic tick, which must tolerate a job that is
            // still legitimately in flight.
            int reaped = jobService.reapStale(Duration.ZERO);
            if (reaped > 0) {
                log.warn("Reaped {} ingestion job(s) left RUNNING by a previous process", reaped);
            }
        } catch (Exception e) {
            log.error("Startup stale-job reap failed", e);
        }
    }

    /**
     * Phase 6's nightly IOC aging sweep — demote compromise findings whose indicator has decayed.
     *
     * <p>A cron rather than a fixed delay, because "nightly" here means "once, in the quiet hours",
     * not "every 24 hours from whenever the app happened to restart". Configurable via
     * {@code secy.compromise.aging-cron}; the placeholder's default (03:30 daily) is repeated here
     * because the test profile replaces {@code application.properties} wholesale.
     *
     * <p>Not a {@link net.jdesive.secy.persistence.entity.Job}: see
     * {@link CompromiseAgingService} for why a bounded single-statement sweep does not belong in a
     * queue built for multi-minute cancellable feed pulls.
     */
    @Scheduled(cron = "${secy.compromise.aging-cron:0 30 3 * * *}")
    public void ageCompromiseFindings() {
        try {
            compromiseAgingService.ageFindings();
        } catch (Exception e) {
            // Never let a bad tick kill the schedule.
            log.error("Compromise IOC aging sweep failed", e);
        }
    }

}
