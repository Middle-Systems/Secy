package net.jdesive.secy.service.azure;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.SourceConnector;
import org.springframework.stereotype.Service;

/**
 * The Azure half of Phase 6b's connector sync (ROADMAP.md — "Source & cloud connectors").
 * {@code connector.getScope()} is a single Azure subscription id.
 *
 * <p><b>Scaffolding stub — not yet implemented.</b> {@code ConnectorSyncService} already dispatches
 * {@code SourceConnectorType.AZURE} rows here (see that enum value's Javadoc for the shape: VMs/ACR
 * repositories enumerated into {@code Asset}s, Microsoft Defender for Cloud's own vulnerability
 * assessments read against them, both persisted via {@code AssetService#applyScan} — the exact path
 * Trivy/Grype/Compliance already use).
 */
@Slf4j
@Service
public class AzureSyncService {

    public IngestResult sync(SourceConnector connector, JobProgress progress) {
        throw new UnsupportedOperationException(
                "Azure connector sync is not yet implemented (Phase 6b scaffolding stub)");
    }

}
