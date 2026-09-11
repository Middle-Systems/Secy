package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * {@code JobRunner}'s entry point for an {@code ASSET_SCAN} job.
 *
 * <p>The {@code SbomIngestJobService} pattern, verbatim and for the same reason: this class is
 * deliberately <b>not</b> {@code @Transactional}, so that the work
 * ({@link AssetService#ingestScanJob}) and the failure path ({@link AssetService#markScanJobFailed})
 * run as two separate transactions on a different bean. Having one method on {@code AssetService}
 * call the other internally would bypass Spring's proxy and silently run the {@code REQUIRES_NEW}
 * failure write outside a transaction of its own — which is exactly when it is needed, since the
 * first transaction has already rolled back.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AssetScanIngestJobService {

    private final AssetService assetService;

    public IngestResult ingest(UUID jobId, JobProgress progress) {
        try {
            return assetService.ingestScanJob(jobId, progress);
        } catch (RuntimeException e) {
            log.error("Asset scan job {} failed to ingest; marking its asset row FAILED", jobId, e);
            assetService.markScanJobFailed(jobId);
            throw e;
        }
    }

}
