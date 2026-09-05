package net.jdesive.secy.config;

import net.jdesive.secy.job.IngestionJobProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.ThreadPoolExecutor;

/**
 * Wiring for the background ingestion queue: the dedicated worker pool, plus {@code @Scheduled}
 * support for the queue poller and the stale-job reaper.
 *
 * <p>{@code @EnableAsync} lives on {@code SecyApplication} and is unrelated — it drives
 * {@code VulnerabilityScanner}'s SBOM scan on the shared {@code applicationTaskExecutor}. Feed
 * ingests get their own pool so a multi-minute NVD pull cannot starve that.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(IngestionJobProperties.class)
public class AsyncConfig {

    /** Bean name the job runner qualifies on. */
    public static final String INGESTION_EXECUTOR = "ingestionTaskExecutor";

    /**
     * Bounded pool for feed ingests.
     *
     * <p>The queue is deliberately tiny: the poller only ever dispatches up to
     * {@code workerPoolSize} jobs at once, so anything beyond that stays QUEUED in the database
     * where a restart can still find it — a durable backlog rather than an in-memory one.
     */
    @Bean(name = INGESTION_EXECUTOR)
    public ThreadPoolTaskExecutor ingestionTaskExecutor(IngestionJobProperties properties) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(properties.getWorkerPoolSize());
        executor.setMaxPoolSize(properties.getWorkerPoolSize());
        executor.setQueueCapacity(properties.getWorkerPoolSize());
        executor.setThreadNamePrefix("ingest-");
        // A rejection is surfaced to the poller, which fails the job with a clear message rather
        // than letting the request thread run a feed pull.
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        // Let an in-flight ingest finish on shutdown; the interrupt is what CANCELLED reflects.
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        return executor;
    }

}
