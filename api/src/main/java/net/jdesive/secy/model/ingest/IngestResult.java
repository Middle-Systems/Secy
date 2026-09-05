package net.jdesive.secy.model.ingest;

/**
 * What a feed ingest actually did. The job runner copies this onto the job row when the run
 * finishes.
 *
 * @param itemsProcessed records written
 * @param message        short summary shown on the job
 */
public record IngestResult(int itemsProcessed, String message) {

    public static IngestResult of(int itemsProcessed, String noun) {
        return new IngestResult(itemsProcessed, itemsProcessed + " " + noun + " ingested");
    }

}
