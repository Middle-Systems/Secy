package net.jdesive.secy.model.ownership;

import net.jdesive.secy.persistence.entity.OwnerType;

import java.util.UUID;

/**
 * A manual ownership assignment (M1b — see ROADMAP.md's "M1b — Ownership model").
 *
 * <p>{@code USER}: {@code userId} required, referencing a registered, enabled account that is a
 * member of the product's tenant; {@code principal} must be absent. {@code TEAM}: {@code principal}
 * required (free text, trimmed); {@code userId} must be absent. See
 * {@code OwnershipService#assignManualProductOwner} for the full validation.
 */
public record ProductOwnerRequest(OwnerType ownerType, UUID userId, String principal) {
}
