package net.jdesive.secy.service.sbom;

/**
 * The uploaded document is not an SBOM Secy can read.
 *
 * <p>Always a client error: the body parsed as JSON but is not CycloneDX, not SPDX 2.2/2.3, or is
 * one of those but malformed beyond use. {@code SBOMController} renders it as
 * {@code 400 Bad Request} with {@link #getMessage()} as the message, so the message is
 * user-facing — it must say what was expected and what arrived.
 */
public class UnsupportedSbomFormatException extends RuntimeException {

    public UnsupportedSbomFormatException(String message) {
        super(message);
    }

    public UnsupportedSbomFormatException(String message, Throwable cause) {
        super(message, cause);
    }

}
