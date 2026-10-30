package net.jdesive.secy.service.vex;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * {@code JobRunner}'s entry point for a {@code VEX_UPLOAD} job — a thin, deliberately non-transactional
 * orchestrator, same shape as {@code SbomIngestJobService}: the work
 * ({@link VexIngestionService#ingestUploadJob}) and the failure path
 * ({@link VexIngestionService#markUploadJobFailed}) are two separate transactions on a different bean,
 * which is what lets Spring's proxy actually apply {@code @Transactional} to each.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VexIngestJobService {

    private final VexIngestionService vexIngestionService;

    public IngestResult ingest(UUID jobId, JobProgress progress) {
        try {
            return vexIngestionService.ingestUploadJob(jobId, progress);
        } catch (RuntimeException e) {
            log.error("VEX upload job {} failed to ingest; marking its document row FAILED", jobId, e);
            vexIngestionService.markUploadJobFailed(jobId);
            throw e;
        }
    }

}
