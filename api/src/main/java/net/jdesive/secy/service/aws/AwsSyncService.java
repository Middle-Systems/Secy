package net.jdesive.secy.service.aws;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.SourceConnector;
import org.springframework.stereotype.Service;

/**
 * The AWS half of Phase 6b's connector sync (ROADMAP.md — "Source & cloud connectors").
 * {@code connector.getScope()} is a single AWS region.
 *
 * <p><b>Scaffolding stub — not yet implemented.</b> {@code ConnectorSyncService} already dispatches
 * {@code SourceConnectorType.AWS} rows here (see that enum value's Javadoc for the shape: EC2/ECR/
 * Lambda enumerated into {@code Asset}s, Amazon Inspector v2's own findings read against them, both
 * persisted via {@code AssetService#applyScan} — the exact path Trivy/Grype/Compliance already use).
 */
@Slf4j
@Service
public class AwsSyncService {

    public IngestResult sync(SourceConnector connector, JobProgress progress) {
        throw new UnsupportedOperationException(
                "AWS connector sync is not yet implemented (Phase 6b scaffolding stub)");
    }

}
