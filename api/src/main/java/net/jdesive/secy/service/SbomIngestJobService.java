package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * {@code JobRunner}'s entry point for a {@code SBOM_UPLOAD} job.
 *
 * <p>A thin orchestrator, deliberately not itself {@code @Transactional}: the actual work
 * ({@link SBOMService#ingestUploadJob}) and the failure path ({@link SBOMService#markUploadJobFailed})
 * are two separate transactions on a different bean. Calling them from here — rather than having one
 * method on {@code SBOMService} call the other internally — is what lets Spring's proxy apply
 * {@code @Transactional} to each one; a self-invoking call within the same bean would silently run
 * outside a transaction (see {@code JobService}'s class comment for the same trap).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SbomIngestJobService {

    private final SBOMService sbomService;

    public IngestResult ingest(UUID jobId, JobProgress progress) {
        try {
            return sbomService.ingestUploadJob(jobId, progress);
        } catch (RuntimeException e) {
            log.error("SBOM upload job {} failed to ingest; marking its SBOM row FAILED", jobId, e);
            sbomService.markUploadJobFailed(jobId);
            throw e;
        }
    }

}
