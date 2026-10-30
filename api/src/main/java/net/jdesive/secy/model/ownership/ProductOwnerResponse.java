package net.jdesive.secy.model.ownership;

import net.jdesive.secy.persistence.entity.OwnerType;
import net.jdesive.secy.persistence.entity.OwnershipInferenceMethod;
import net.jdesive.secy.persistence.entity.OwnershipLink;
import net.jdesive.secy.persistence.entity.OwnershipSource;

import java.time.LocalDateTime;
import java.util.UUID;

/** An ownership link on a product. Never carries a tenant id — see {@code TenantOwnedEntity}. */
public record ProductOwnerResponse(
        UUID id,
        UUID productId,
        OwnerType ownerType,
        UUID userId,
        String userEmail,
        String userDisplayName,
        String principal,
        OwnershipSource source,
        OwnershipInferenceMethod inferenceMethod,
        String evidence,
        UUID assignedById,
        LocalDateTime createdAt) {

    public static ProductOwnerResponse from(OwnershipLink link) {
        return new ProductOwnerResponse(
                link.getId(),
                link.getProduct() == null ? null : link.getProduct().getId(),
                link.getOwnerType(),
                link.getUser() == null ? null : link.getUser().getId(),
                link.getUser() == null ? null : link.getUser().getEmail(),
                link.getUser() == null ? null : link.getUser().getDisplayName(),
                link.getPrincipal(),
                link.getSource(),
                link.getInferenceMethod(),
                link.getEvidence(),
                link.getAssignedBy() == null ? null : link.getAssignedBy().getId(),
                link.getCreatedAt());
    }
}
