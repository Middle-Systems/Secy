package net.jdesive.secy.service;

/**
 * A malformed tag key/value input to {@link ProductTaggingService} — a bad tag-key configuration
 * update, a malformed {@code tag=key=value} upload param, or a tag value that collides with another
 * product's. Mapped to {@code 400} by the controllers that call into this service.
 */
public class InvalidProductTagException extends RuntimeException {

    public InvalidProductTagException(String message) {
        super(message);
    }
}
