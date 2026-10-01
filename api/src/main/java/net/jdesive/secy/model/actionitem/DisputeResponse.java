package net.jdesive.secy.model.actionitem;

import net.jdesive.secy.persistence.entity.Job;

import java.util.UUID;

/** {@code POST /action-items/{id}/disputes}'s 202 body (M1k). Poll {@code GET /jobs/{id}} on {@link #job}. */
public record DisputeResponse(Job job, UUID vexDocumentId, ActionItemEventResponse event) {
}
