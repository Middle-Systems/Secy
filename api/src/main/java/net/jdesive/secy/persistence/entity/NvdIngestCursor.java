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
 * modified in a window, capped at 120 days per request. Two distinct sweeps use this one row:
 *
 * <ul>
 *   <li><b>Bootstrap</b> (no {@link #lastModified} yet — the very first ingest ever): walks
 *       <em>backward</em> from now toward a fixed early epoch, newest data first, tracked by
 *       {@link #oldestSweptModifiedDate}. Newest-first on purpose: a CVE's {@code lastModified} is
 *       usually far more recent than its {@code published} date — NVD's own bulk re-analysis and
 *       CVSS-rescoring passes cluster in recent calendar time regardless of when a CVE was
 *       originally published, so a window anchored to a CVE's own original era is usually
 *       nearly empty. Walking forward from 1999 spends a long time on genuinely-empty history
 *       before reaching the recent, densely-modified window where the actionable data actually
 *       is. Walking backward surfaces that data first.</li>
 *   <li><b>Routine incremental</b> (once {@link #lastModified} is set): a small forward sweep
 *       from there to now — bootstrap already covers ancient history, so there is no "years of
 *       empty windows" problem here to route around.</li>
 * </ul>
 *
 * <p>Persisted again after <b>each window completes</b> in either sweep, not just once at the end
 * — so a run interrupted partway only has to redo its current window on the next attempt, not the
 * entire feed or the entire remaining bootstrap. Advancing mid-window would turn a failed pull
 * into permanently skipped CVEs, the same invariant {@link OsvEcosystemCursor} documents.
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

    /**
     * The forward high-water mark: everything with {@code lastModified} at or before this has been
     * captured. Null until the backward bootstrap sweep finishes reaching the epoch — routine
     * incremental sweeps only run once this is set.
     */
    @Column(name = "last_modified")
    private LocalDateTime lastModified;

    /**
     * The backward bootstrap sweep's frontier: everything with {@code lastModified} at or after
     * this (and before wherever the sweep started) has been captured. Null before bootstrap starts
     * and again once it finishes — {@link #lastModified} takes over from there.
     */
    @Column(name = "oldest_swept_modified_date")
    private LocalDateTime oldestSweptModifiedDate;

    /** When the last successful window finished. Drives a "feed freshness" display. */
    @Column(name = "last_ingested_at")
    private LocalDateTime lastIngestedAt;

}
