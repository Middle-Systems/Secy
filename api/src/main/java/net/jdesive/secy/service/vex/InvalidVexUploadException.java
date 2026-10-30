package net.jdesive.secy.service.vex;

/**
 * A malformed VEX upload request parameter — bad/missing {@code ?origin=}, an unrecognised
 * precedence policy. Mapped to {@code 400} by {@code VexController}, same treatment as
 * {@code InvalidLifecycleStageException} for SBOM uploads: a request that can never succeed must
 * never queue a job or write anything.
 */
public class InvalidVexUploadException extends RuntimeException {

    public InvalidVexUploadException(String message) {
        super(message);
    }

}
