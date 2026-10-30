package net.jdesive.secy.service.access;

/**
 * A malformed {@code PATCH /tenant/members/{userId}} request — both {@code roles} and
 * {@code resetRolesToDefault=true} set, nothing set at all, or a null element in {@code roles}.
 * Mapped to {@code 400} by {@code TenantAccessController}, mirroring
 * {@code InvalidActionItemException}'s role.
 */
public class InvalidTenantAccessException extends RuntimeException {

    public InvalidTenantAccessException(String message) {
        super(message);
    }

}
