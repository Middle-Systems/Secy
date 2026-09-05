package net.jdesive.secy.persistence.entity;

/**
 * Lifecycle of an ingestion {@link Job}.
 *
 * <p>{@code QUEUED -> RUNNING -> (SUCCEEDED | FAILED | CANCELLED)}. The three terminal states are
 * final: nothing — not the worker, not the reaper — moves a job out of one again.
 */
public enum JobStatus {

    /** Persisted and waiting for a worker to claim it. */
    QUEUED,

    /** Claimed by a worker and currently pulling the feed. */
    RUNNING,

    /** Finished; the feed was ingested. */
    SUCCEEDED,

    /** The ingest threw, or the reaper found the job stalled past the timeout. */
    FAILED,

    /** The worker observed an interrupt between batches and stopped early. */
    CANCELLED;

    /** True for the states a job never leaves. */
    public boolean isTerminal() {
        return this == SUCCEEDED || this == FAILED || this == CANCELLED;
    }

    /** True while the job still owns the "one active job per type" slot. */
    public boolean isActive() {
        return !isTerminal();
    }

}
