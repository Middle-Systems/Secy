package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * {@code JobRunner}'s entry point for a {@code COMPLIANCE_SCAN} job.
 *
 * <p>The {@code AssetScanIngestJobService} pattern, verbatim and for the same reason: this class is
 * deliberately <b>not</b> {@code @Transactional}, so the work
 * ({@link ComplianceService#ingestScanJob}) and the failure path
 * ({@link ComplianceService#markScanJobFailed}) run as two separate transactions on a different
 * bean. Calling one from the other internally would bypass Spring's proxy and silently run the
 * {@code REQUIRES_NEW} failure write outside a transaction — which is exactly when it is needed,
 * since the first has already rolled back.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ComplianceScanIngestJobService {

    private final ComplianceService complianceService;

    public IngestResult ingest(UUID jobId, JobProgress progress) {
        try {
            return complianceService.ingestScanJob(jobId, progress);
        } catch (RuntimeException e) {
            log.error("Compliance scan job {} failed; marking its report row FAILED", jobId, e);
            complianceService.markScanJobFailed(jobId);
            throw e;
        }
    }

}
