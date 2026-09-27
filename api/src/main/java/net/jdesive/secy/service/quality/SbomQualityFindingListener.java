package net.jdesive.secy.service.quality;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.events.SbomUploadedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Fires M1h's SBOM-quality finding reconciliation after every SBOM ingestion commits — reuses the
 * existing {@link SbomUploadedEvent}, exactly like {@code QuantumFindingListener}/
 * {@code LifecycleDiffListener}, and for the same reason: the <em>score</em> itself
 * ({@code SbomQualityScorer.score}) has no cross-document dependency and runs inline in
 * {@code SBOMService.ingestDocument} (M1c's Pass A pattern), but the <em>finding</em> is keyed on a
 * shared (product, stage-slot) row and its reconciliation reads the product's active-slot set (to
 * sweep superseded slots) — so it needs the same after-commit treatment, to avoid the identical race
 * between two concurrently-ingesting uploads to the same product.
 *
 * <p>Deliberately synchronous (not {@code @Async}): runs on the same job thread as the ingestion, so
 * it completes before the job is marked {@code COMPLETED}, keeping tests deterministic. A
 * {@code @Transactional} test never commits, so this listener never fires there either.
 *
 * <p>Never fails the ingestion: a reconciliation failure is caught and logged, never rethrown.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SbomQualityFindingListener {

    private final SbomQualityFindingService sbomQualityFindingService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onSbomUploaded(SbomUploadedEvent event) {
        try {
            sbomQualityFindingService.reconcileForSbom(event.sbomId());
        } catch (RuntimeException e) {
            log.error("SBOM quality finding reconciliation failed for SBOM {}: {}",
                    event.sbomId(), e.getMessage(), e);
        }
    }

}
