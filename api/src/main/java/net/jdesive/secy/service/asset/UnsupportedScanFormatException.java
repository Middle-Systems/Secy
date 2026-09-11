package net.jdesive.secy.service.asset;

/**
 * The uploaded document is not the scanner report the endpoint expects.
 *
 * <p>Handled as a {@code 400} by {@code AssetController}, before anything is stored or queued —
 * the same principle {@code UnsupportedSbomFormatException} established in Phase 3: a client must
 * never get a {@code 202} for a document that can never succeed.
 */
public class UnsupportedScanFormatException extends RuntimeException {

    public UnsupportedScanFormatException(String message) {
        super(message);
    }

    public UnsupportedScanFormatException(String message, Throwable cause) {
        super(message, cause);
    }

}
