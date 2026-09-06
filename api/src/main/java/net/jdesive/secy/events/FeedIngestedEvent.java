package net.jdesive.secy.events;

import net.jdesive.secy.persistence.entity.JobType;

import java.util.UUID;

/**
 * Published by {@code JobRunner} when an ingestion job reaches {@code SUCCEEDED}.
 *
 * <p>Exists so work that has to happen <em>after</em> a feed changes — re-running the actionable
 * funnel over existing alerts, principally — does not need a job row of its own. Re-enrichment is a
 * consequence of an ingest, not something a user queued, so it stays off {@code GET /jobs}.
 *
 * @param jobId the ingestion job that just succeeded
 * @param type  which feed it pulled
 */
public record FeedIngestedEvent(UUID jobId, JobType type) {
}
