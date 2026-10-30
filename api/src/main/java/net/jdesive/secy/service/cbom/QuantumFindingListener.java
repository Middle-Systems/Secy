package net.jdesive.secy.service.cbom;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.events.SbomUploadedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Fires M1g's quantum-vulnerability finding reconciliation after every SBOM ingestion commits —
 * reuses the existing {@link SbomUploadedEvent}, exactly like {@code LifecycleDiffListener}, and for
 * the same reasons: crypto-asset *extraction and classification* has no cross-document dependency and
 * runs inline in {@code SBOMService.ingestDocument} (M1c's Pass A pattern), but finding
 * *reconciliation* does — a finding must be carried forward across re-uploads and, for a staged
 * product, its candidate set is the union of every active stage slot (see
 * {@code SbomCorrelationScope}) — so it needs the same after-commit treatment
 * {@code LifecycleDiffListener} gives lifecycle drift, to avoid the identical race between two
 * concurrently-ingesting stage uploads.
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
public class QuantumFindingListener {

    private final QuantumFindingService quantumFindingService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onSbomUploaded(SbomUploadedEvent event) {
        try {
            quantumFindingService.reconcileForSbom(event.sbomId());
        } catch (RuntimeException e) {
            log.error("Quantum-vulnerability finding reconciliation failed for SBOM {}: {}",
                    event.sbomId(), e.getMessage(), e);
        }
    }

}
