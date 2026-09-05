package net.jdesive.secy.model.ingest;

/**
 * Callback a feed service reports through while it ingests, so the job row can show progress while
 * the run is still going.
 *
 * <p>Lives in {@code model} rather than {@code job} on purpose: the feed services in
 * {@code service} implement against it and the runner in {@code job} supplies it, so putting it in
 * either of those packages would make the two depend on each other.
 */
@FunctionalInterface
public interface JobProgress {

    /** A no-op sink, for the plain {@code ingest()} entry points that nothing is watching. */
    JobProgress NOOP = (itemsProcessed, message) -> {
    };

    /**
     * Report the running total. Called between batches, not per record — implementations may
     * throttle how often they actually write.
     *
     * @param itemsProcessed records written so far
     * @param message        short human-readable status line
     */
    void report(int itemsProcessed, String message);

    /**
     * Whether the ingest should stop early. Feed services check this between batches; the default
     * reads the worker thread's interrupt flag, which is what a pool shutdown sets.
     */
    default boolean isCancelled() {
        return Thread.currentThread().isInterrupted();
    }

}
