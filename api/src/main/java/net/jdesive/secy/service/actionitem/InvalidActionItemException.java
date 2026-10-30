package net.jdesive.secy.service.actionitem;

/**
 * A malformed {@code ActionItemService} request — bad scope, an unknown/PROVENANCE finding ref, a
 * bad assignee/approver, an incomplete risk-acceptance, or a rejected {@code NOT_AFFECTED} status
 * request. Mapped to {@code 400} by {@code ActionItemController}, mirroring
 * {@code InvalidOwnershipException}'s role for {@code ProductOwnershipController}.
 */
public class InvalidActionItemException extends RuntimeException {

    public InvalidActionItemException(String message) {
        super(message);
    }

}
