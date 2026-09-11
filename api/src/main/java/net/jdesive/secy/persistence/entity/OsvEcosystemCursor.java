package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Per-ecosystem high-water mark for the OSV mirror.
 *
 * <p>OSV publishes one {@code all.zip} per ecosystem at
 * {@code https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip}, each holding one
 * JSON file per advisory. A full pull of every ecosystem is large and mostly unchanged between runs,
 * so the ingester records the newest record {@code modified} timestamp it has seen for an ecosystem
 * and, on the next run, skips records at or below it.
 *
 * <p>One row per ecosystem, keyed by the OSV ecosystem name exactly as it appears in the export
 * path. Owned by the OSV feed ingester; defined here so that agent has a schema to target and this
 * phase's migration can create the table. Nothing in the correlation path reads it.
 */
@Getter
@Setter
@Entity
@Table(name = "osv_ecosystem_cursor")
public class OsvEcosystemCursor {

    /** OSV ecosystem name as it appears in the export path — {@code npm}, {@code Maven}, {@code PyPI}. */
    @Id
    @Column(length = 64)
    private String ecosystem;

    /**
     * The newest {@code modified} timestamp among the records ingested for this ecosystem. The next
     * run skips anything not strictly newer.
     *
     * <p>Advance it only after the whole ecosystem has been written; a mid-run advance turns a
     * failed pull into permanently skipped advisories.
     */
    @Column(name = "last_modified")
    private LocalDateTime lastModified;

    /** When the last successful pull for this ecosystem finished. Drives the "feed freshness" display. */
    @Column(name = "last_ingested_at")
    private LocalDateTime lastIngestedAt;

}
