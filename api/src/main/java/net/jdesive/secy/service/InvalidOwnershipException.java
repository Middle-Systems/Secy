package net.jdesive.secy.service;

/**
 * A malformed manual ownership request to {@link OwnershipService} — a missing/unknown owner type,
 * a bad {@code userId}/{@code principal} combination, or an invalid principal. Mapped to {@code 400}
 * by {@code ProductOwnershipController}.
 */
public class InvalidOwnershipException extends RuntimeException {

    public InvalidOwnershipException(String message) {
        super(message);
    }
}
