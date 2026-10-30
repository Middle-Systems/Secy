package net.jdesive.secy.service.vex;

import net.jdesive.secy.persistence.entity.Job;

import java.util.UUID;

/** {@code VexAuthoringService.author}'s result — the queued job and the placeholder document id. */
public record AuthoredVex(Job job, UUID documentId) {
}
