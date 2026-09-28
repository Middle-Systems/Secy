package net.jdesive.secy.model.actionitem;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * An action item's risk-acceptance record — null unless the stored status is {@code RISK_ACCEPTED}
 * (§5's schema-only policy: no approval enforcement, {@code approvedById} may equal {@code acceptedById}).
 */
public record RiskAcceptance(
        LocalDateTime until,
        LocalDateTime acceptedAt,
        UUID acceptedById,
        String acceptedByName,
        String justification,
        UUID approvedById,
        String approvedByName,
        String approvalNote) {
}
