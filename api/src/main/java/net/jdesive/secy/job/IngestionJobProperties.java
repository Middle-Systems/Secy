package net.jdesive.secy.job;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code secy.jobs.*} — see the "Ingestion jobs" block in {@code application.properties}.
 *
 * <p>Every default is repeated in the {@code @Scheduled} placeholders that read these keys, because
 * the test profile replaces {@code application.properties} outright rather than merging with it.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.jobs")
public class IngestionJobProperties {

    /** Concurrent ingestions. Also caps how many jobs the poller claims per tick. */
    private int workerPoolSize = 2;

    /** A RUNNING job untouched for longer than this is failed by the reaper. */
    private Duration staleTimeout = Duration.ofMinutes(30);

    /** How often the poller looks for QUEUED jobs. */
    private Duration pollInterval = Duration.ofSeconds(10);

    /**
     * Whether the poller and reaper timers run at all. Off in the test profile — see
     * {@link JobScheduler}. Read by {@code @ConditionalOnProperty}, not from this field.
     */
    private boolean schedulerEnabled = true;

}
