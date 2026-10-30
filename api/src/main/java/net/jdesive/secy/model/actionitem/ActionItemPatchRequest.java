package net.jdesive.secy.model.actionitem;

import jakarta.validation.constraints.Size;
import net.jdesive.secy.persistence.entity.RemediationStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Body of {@code PATCH /action-items/{id}} — partial update, null fields left untouched.
 *
 * @param status                      one of OPEN/IN_PROGRESS/RISK_ACCEPTED/RESOLVED — NOT_AFFECTED
 *                                    is derived-only and rejected with 400
 * @param assigneeUserId              new assignee, or null to leave the current one unchanged
 * @param unassign                    true clears the assignee — the explicit flag
 *                                    {@code TriagePatchRequest} was missing
 * @param title                       new title, or null to leave unchanged
 * @param description                 new description, or null to leave unchanged
 * @param riskAcceptedUntil           required (strictly future) when entering/renewing RISK_ACCEPTED
 * @param riskAcceptanceJustification required (non-blank) when entering/renewing RISK_ACCEPTED
 * @param riskApprovedByUserId        optional approver, may equal the acting user
 * @param riskApprovalNote            optional note alongside the approver
 * @param comment                     an optional note recorded alongside this change
 */
public record ActionItemPatchRequest(
        RemediationStatus status,
        UUID assigneeUserId,
        Boolean unassign,
        @Size(max = 255, message = "title must be at most 255 characters") String title,
        @Size(max = 4096, message = "description must be at most 4096 characters") String description,
        LocalDateTime riskAcceptedUntil,
        @Size(max = 4096, message = "riskAcceptanceJustification must be at most 4096 characters") String riskAcceptanceJustification,
        UUID riskApprovedByUserId,
        @Size(max = 4096, message = "riskApprovalNote must be at most 4096 characters") String riskApprovalNote,
        @Size(max = 4096, message = "comment must be at most 4096 characters") String comment) {
}
