package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One background feed ingestion — enqueued by {@code POST /{feed}/ingest}, executed by the worker
 * pool, polled by the UI through {@code GET /jobs/{id}}.
 *
 * <p>Several threads look at a job row: the poller that claims it, the worker that reports progress
 * and the reaper that fails stalled runs. {@link #version} turns every one of those writes into an
 * optimistic-locking check, so a stale writer loses instead of silently clobbering a newer state.
 */
@Getter
@Setter
@ToString
@Entity
@Table(name = "ingestion_job")
public class Job {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private JobType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private JobStatus status = JobStatus.QUEUED;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    /** Set when a worker claims the job. Null while {@code QUEUED}. */
    private LocalDateTime startedAt;

    /** Set on the transition to a terminal status. Null until then. */
    private LocalDateTime finishedAt;

    /** Running count of records the feed service has written so far. */
    @Column(nullable = false)
    private int itemsProcessed;

    /** Last progress line, or the failure message once the job has failed. */
    @Column(length = 2048)
    private String message;

    /** Authenticated principal name if the request carried one, otherwise {@code "system"}. */
    private String triggeredBy;

    /** Optimistic lock — see the class comment. */
    @Version
    @Column(nullable = false)
    private long version;

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

}
