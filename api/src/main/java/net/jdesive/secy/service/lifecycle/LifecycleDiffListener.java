package net.jdesive.secy.service.lifecycle;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.events.SbomUploadedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Fires the M1e lifecycle diff after every SBOM ingestion commits — reuses the existing
 * {@link SbomUploadedEvent} (the same one {@code VulnerabilityScanner} listens for) rather than a new
 * event or {@code JobType}: nothing about the diff needs queuing, dedup or cancellation, it is cheap
 * (two component projections per pair, at most three pairs), and every ingestion path already
 * publishes this event.
 *
 * <h2>Why after-commit, not inline in {@code SBOMService.ingestDocument}</h2>
 *
 * <p>{@code secy.ingestion.worker-pool-size} defaults to 2, so a Source and a Build upload from one CI
 * pipeline can be ingesting concurrently. Diffing inline, inside each upload's own transaction, would
 * read before either commits — under READ COMMITTED neither transaction would see the other's
 * not-yet-committed components, and the drift would be permanently missed, not just delayed. Running
 * after commit means whichever SBOM commits last sees the other's already-committed components, and
 * since <em>both</em> sides publish this event and trigger their own diff run, the pair is diffed from
 * at least one side no matter which upload finishes first. (M1c's Pass A/B ran inline because it had
 * no cross-SBOM ordering dependency; this one does.)
 *
 * <h2>Not {@code @Async}</h2>
 *
 * <p>Deliberately synchronous, unlike {@code VulnerabilityScanner}'s listener: the diff runs on the
 * same job thread as the ingestion, inside {@code JobRunner}'s call, so it completes before the job is
 * marked {@code COMPLETED} — keeping tests deterministic (poll the job, then assert on drift findings,
 * no extra {@code await()}). A {@code @Transactional} test never commits, so this listener never fires
 * there either — zero behavior change for the existing transactional correlation/detection suites.
 *
 * <h2>Never fails the ingestion</h2>
 *
 * <p>A diff failure is caught and logged, never rethrown: the SBOM upload it rode in on already
 * succeeded (its own transaction already committed) by the time this runs, and a diffing bug must
 * never turn an already-successful ingestion into a failed job.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class LifecycleDiffListener {

    private final LifecycleDiffService lifecycleDiffService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onSbomUploaded(SbomUploadedEvent event) {
        try {
            lifecycleDiffService.runForSbom(event.sbomId());
        } catch (RuntimeException e) {
            log.error("Lifecycle diff failed for SBOM {}: {}", event.sbomId(), e.getMessage(), e);
        }
    }

}
