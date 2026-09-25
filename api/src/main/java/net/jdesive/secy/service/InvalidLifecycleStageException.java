package net.jdesive.secy.service;

/**
 * An unrecognised {@code ?stage=} value on an SBOM upload endpoint (M1e). Mapped to {@code 400} by
 * {@code SBOMController} — a request that can never succeed must never queue a job.
 */
public class InvalidLifecycleStageException extends RuntimeException {

    public InvalidLifecycleStageException(String message) {
        super(message);
    }
}
