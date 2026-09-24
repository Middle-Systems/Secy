package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * NVD's high-water mark — the same single-feed-wide idea {@link OsvEcosystemCursor} applies per
 * package ecosystem, just one row instead of many: NVD is one global feed, not one per ecosystem.
 *
 * <p>NVD's CVE API accepts {@code lastModStartDate}/{@code lastModEndDate} to pull only records
 * modified in a window, capped at 120 days per request. {@code NVDService} sweeps from this cursor's
 * {@link #lastModified} (or a fixed early epoch, on the very first ever ingest) to now in ≤119-day
 * windows, and persists this row again after <b>each</b> window completes — not just at the end of
 * the whole sweep — so a run interrupted partway only has to redo its current window on the next
 * attempt, not the entire feed. Advancing mid-window would turn a failed pull into permanently
 * skipped CVEs, the same invariant {@link OsvEcosystemCursor} documents.
 *
 * <p>One fixed row, id {@code "nvd"} — a table rather than a single mutable column so the shape
 * matches {@code OsvEcosystemCursor} and so {@link #lastIngestedAt} can back a "feed freshness"
 * display the same way. Nothing in the correlation path reads it.
 */
@Getter
@Setter
@Entity
@Table(name = "nvd_ingest_cursor")
public class NvdIngestCursor {

    /** Always {@code "nvd"} — there is exactly one row. */
    @Id
    @Column(length = 32)
    private String id;

    /** The newest CVE {@code lastModified} timestamp swept so far. Null before the first ingest. */
    @Column(name = "last_modified")
    private LocalDateTime lastModified;

    /** When the last successful window finished. Drives a "feed freshness" display. */
    @Column(name = "last_ingested_at")
    private LocalDateTime lastIngestedAt;

}
