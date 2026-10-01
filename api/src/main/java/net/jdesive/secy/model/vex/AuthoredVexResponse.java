package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.Job;

import java.util.UUID;

/** {@code POST /vex/statements}'s 202 body (M1k). Poll {@code GET /jobs/{id}} on {@link #job}. */
public record AuthoredVexResponse(Job job, UUID documentId) {
}
