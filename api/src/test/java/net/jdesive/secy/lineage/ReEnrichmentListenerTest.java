package net.jdesive.secy.lineage;

import net.jdesive.secy.events.FeedIngestedEvent;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.EnrichmentService;
import net.jdesive.secy.service.ReEnrichmentListener;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link ReEnrichmentListener} exercised by direct construction (no Spring context) —
 * {@code @Async} just means "runs on another thread" in production, it does not change what the
 * method itself decides to do when called directly.
 */
class ReEnrichmentListenerTest {

    @Test
    void lineageRebuildDoesNotTriggerReEnrichment() {
        EnrichmentService enrichmentService = mock(EnrichmentService.class);
        ReEnrichmentListener listener = new ReEnrichmentListener(enrichmentService);

        listener.onFeedIngested(new FeedIngestedEvent(UUID.randomUUID(), JobType.LINEAGE_REBUILD));

        verify(enrichmentService, never()).reEnrichAll();
    }

    @Test
    void nvdDoesNotTriggerReEnrichment() {
        EnrichmentService enrichmentService = mock(EnrichmentService.class);
        ReEnrichmentListener listener = new ReEnrichmentListener(enrichmentService);

        listener.onFeedIngested(new FeedIngestedEvent(UUID.randomUUID(), JobType.NVD));

        verify(enrichmentService, never()).reEnrichAll();
    }

    @Test
    void ignoresVexUpload() {
        EnrichmentService enrichmentService = mock(EnrichmentService.class);
        ReEnrichmentListener listener = new ReEnrichmentListener(enrichmentService);

        listener.onFeedIngested(new FeedIngestedEvent(UUID.randomUUID(), JobType.VEX_UPLOAD));

        verify(enrichmentService, never()).reEnrichAll();
    }

    @Test
    void riskRescoreDoesNotTriggerReEnrichment() {
        EnrichmentService enrichmentService = mock(EnrichmentService.class);
        ReEnrichmentListener listener = new ReEnrichmentListener(enrichmentService);

        listener.onFeedIngested(new FeedIngestedEvent(UUID.randomUUID(), JobType.RISK_RESCORE));

        verify(enrichmentService, never()).reEnrichAll();
    }

    @Test
    void kevStillTriggersReEnrichment() {
        EnrichmentService enrichmentService = mock(EnrichmentService.class);
        when(enrichmentService.reEnrichAll()).thenReturn(3);
        ReEnrichmentListener listener = new ReEnrichmentListener(enrichmentService);

        listener.onFeedIngested(new FeedIngestedEvent(UUID.randomUUID(), JobType.KEV));

        verify(enrichmentService, times(1)).reEnrichAll();
    }

}
