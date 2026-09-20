package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.service.github.GitHubSyncService;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * {@code JobRunner}'s entry point for a {@code CONNECTOR_SYNC} job, and the dispatch point by
 * {@link SourceConnector#getType()} — today just {@code GITHUB}, with room for {@code AWS}/
 * {@code AZURE} to become another {@code case} here later without another {@code JobType}
 * (ROADMAP.md's Phase 6b notes that shape explicitly).
 *
 * <p>The {@code AssetScanIngestJobService}/{@code ComplianceScanIngestJobService} pattern: this
 * class is deliberately <b>not</b> {@code @Transactional} itself, so the lifecycle writes
 * ({@link SourceConnectorService#beginSyncJob}, {@link SourceConnectorService#completeSync},
 * {@link SourceConnectorService#markSyncFailed}) run as their own short transactions on a different
 * bean — calling one {@code @Transactional} method from another on the same bean would bypass
 * Spring's proxy, which is exactly what would silently break {@code markSyncFailed}'s
 * {@code REQUIRES_NEW}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ConnectorSyncService {

    private final SourceConnectorService sourceConnectorService;
    private final GitHubSyncService gitHubSyncService;

    public IngestResult ingest(UUID jobId, JobProgress progress) {
        SourceConnector connector = sourceConnectorService.beginSyncJob(jobId);
        try {
            IngestResult result = switch (connector.getType()) {
                case GITHUB -> gitHubSyncService.sync(connector, progress);
            };
            sourceConnectorService.completeSync(connector.getId());
            return result;
        } catch (RuntimeException e) {
            log.error("Connector sync job {} failed for connector {} ({})",
                    jobId, connector.getId(), connector.getName(), e);
            sourceConnectorService.markSyncFailed(connector.getId());
            throw e;
        }
    }

}
