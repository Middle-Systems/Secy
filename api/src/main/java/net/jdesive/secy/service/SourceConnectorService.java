package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.SourceConnectorRepository;
import net.jdesive.secy.persistence.entity.SourceConnector;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * CRUD for {@link SourceConnector} rows and the {@code CONNECTOR_SYNC} job lifecycle around them.
 *
 * <p>The lifecycle methods ({@link #beginSyncJob}, {@link #completeSync}, {@link #markSyncFailed})
 * are deliberately separate, short {@code @Transactional} methods rather than one method that does
 * the whole sync — {@code ConnectorSyncService} calls each of them from outside a transaction of its
 * own, around the (slow, network-bound) work {@code GitHubSyncService} does in between. See that
 * class for why. They mirror {@code AssetService}'s {@code ingestScanJob}/{@code markScanJobFailed}
 * split for the same reason the Javadoc there gives: calling one {@code @Transactional} method from
 * another on the <em>same</em> bean bypasses Spring's proxy, so these must live on a bean a different
 * caller invokes them through.
 */
@Service
@RequiredArgsConstructor
public class SourceConnectorService {

    private final SourceConnectorRepository sourceConnectorRepository;

    /* ------------------------------------------------------------------ */
    /* CRUD                                                                */
    /* ------------------------------------------------------------------ */

    @Transactional
    public SourceConnector create(SourceConnector connector) {
        connector.setId(null);
        connector.setStatus(SourceConnector.STATUS_QUEUED);
        connector.setLastSyncedAt(null);
        connector.setJobId(null);
        return sourceConnectorRepository.save(connector);
    }

    @Transactional(readOnly = true)
    public Page<SourceConnector> list(int page, int size) {
        return sourceConnectorRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size));
    }

    @Transactional(readOnly = true)
    public Optional<SourceConnector> get(UUID id) {
        return sourceConnectorRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public boolean exists(UUID id) {
        return sourceConnectorRepository.existsById(id);
    }

    /**
     * Removes the connector row only. Deliberately does NOT cascade to the {@code Product}s/
     * {@code SBOM}s it created — those are real inventory now, independent of whichever connector
     * (if any) introduced them, exactly as an SBOM uploaded manually outlives the upload request
     * that created it. Deleting a connector is "stop syncing this", not "undo everything it ever
     * found".
     *
     * @return true if a connector with that id existed
     */
    @Transactional
    public boolean delete(UUID id) {
        if (!sourceConnectorRepository.existsById(id)) {
            return false;
        }
        sourceConnectorRepository.deleteById(id);
        return true;
    }

    /* ------------------------------------------------------------------ */
    /* Sync trigger (POST /connectors/{id}/sync)                          */
    /* ------------------------------------------------------------------ */

    /** Point an existing connector at a fresh {@code CONNECTOR_SYNC} job. @return empty when the id is unknown */
    @Transactional
    public Optional<SourceConnector> queueSync(UUID connectorId, UUID jobId) {
        return sourceConnectorRepository.findById(connectorId).map(connector -> {
            connector.setStatus(SourceConnector.STATUS_QUEUED);
            connector.setJobId(jobId);
            return sourceConnectorRepository.saveAndFlush(connector);
        });
    }

    /* ------------------------------------------------------------------ */
    /* Job lifecycle — called by ConnectorSyncService                     */
    /* ------------------------------------------------------------------ */

    /**
     * Find the connector waiting on {@code jobId} and move it to {@code PROCESSING}.
     *
     * @throws IllegalStateException if no connector is waiting on this job
     */
    @Transactional
    public SourceConnector beginSyncJob(UUID jobId) {
        SourceConnector connector = sourceConnectorRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No source connector is waiting on sync job " + jobId));
        connector.setStatus(SourceConnector.STATUS_PROCESSING);
        return sourceConnectorRepository.saveAndFlush(connector);
    }

    /** The sync finished with at least one repo ingested, or nothing to ingest at all. */
    @Transactional
    public void completeSync(UUID connectorId) {
        sourceConnectorRepository.findById(connectorId).ifPresent(connector -> {
            connector.setStatus(SourceConnector.STATUS_COMPLETED);
            connector.setLastSyncedAt(LocalDateTime.now());
            sourceConnectorRepository.save(connector);
        });
    }

    /**
     * Every repo the sync targeted failed. {@code REQUIRES_NEW} so this write survives even if it
     * is reached after a nested {@code @Transactional} call rolled its own transaction back — the
     * same reasoning {@code AssetService#markScanJobFailed} documents, applied defensively here even
     * though {@code ConnectorSyncService#ingest} itself holds no surrounding transaction.
     * {@link #lastSyncedAt} is left exactly where it was: a failed sync degrades the connector to
     * stale, not empty.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markSyncFailed(UUID connectorId) {
        sourceConnectorRepository.findById(connectorId).ifPresent(connector -> {
            connector.setStatus(SourceConnector.STATUS_FAILED);
            sourceConnectorRepository.save(connector);
        });
    }

}
