package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.events.FeedIngestedEvent;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Re-runs the actionable funnel over existing alerts after a feed ingest changed what the feeds
 * know.
 *
 * <p>Without this, an alert raised on Monday for a CVE that CISA adds to KEV on Tuesday would sit
 * at {@code actionable = false} until the next SBOM upload. The listener is {@code @Async} so a
 * long re-enrichment never holds up the ingestion worker that fired the event.
 *
 * <p><b>Which feeds trigger it.</b> Everything except {@link JobType#NVD}. KEV and EPSS both feed
 * the funnel predicate directly; a future exploit-index feed changes {@code exploitMaturity}, and
 * gets re-enrichment for free by virtue of not being NVD — no edit here required. NVD is excluded
 * because a full CVE pull is the one ingest whose effect on alerts (a refreshed {@code cvssScore}
 * snapshot) does not change whether anything is actionable, and re-enriching the whole alert table
 * on the back of a multi-minute NVD pull is not worth it.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ReEnrichmentListener {

    private final EnrichmentService enrichmentService;

    @Async
    @EventListener
    public void onFeedIngested(FeedIngestedEvent event) {
        if (event.type() == JobType.NVD) {
            return;
        }
        try {
            int reEnriched = enrichmentService.reEnrichAll();
            log.info("Re-enriched {} alerts after the {} ingest (job {})",
                    reEnriched, event.type(), event.jobId());
        } catch (Exception e) {
            // A failed re-enrichment must not mark the (successful) ingest as broken; the next
            // ingest of any feed retries it.
            log.error("Re-enrichment after the {} ingest (job {}) failed", event.type(), event.jobId(), e);
        }
    }

}
