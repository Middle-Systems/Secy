package net.jdesive.secy.model.actionitem;

import net.jdesive.secy.persistence.entity.VexJustification;

import java.util.UUID;

/**
 * {@code POST /action-items/{id}/disputes} body (M1k — ROADMAP.md's "Role-based views" §7). A
 * dispute is an authored TENANT OpenVEX {@code not_affected} statement, scoped to the one finding
 * named here — see {@code ActionItemDisputeService}.
 *
 * @param findingId       must be a {@code VULNERABILITY} finding already linked to this item
 * @param justification   optional (either this or a non-blank {@link #impactStatement} is required
 *                        for the authored statement to not be reasonless)
 * @param impactStatement required, non-blank, ≤4096 chars
 */
public record DisputeFindingRequest(UUID findingId, VexJustification justification, String impactStatement) {
}
