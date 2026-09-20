package net.jdesive.secy.persistence.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Where Secy should look for inventory on its own, and what it found last time (Phase 6b,
 * ROADMAP.md — "Source & cloud connectors").
 *
 * <h2>No credential field</h2>
 *
 * <p>Deliberately: the roadmap locks this to one token per Secy instance, not per connector —
 * {@code SECY_GITHUB_TOKEN}, read the same way {@code NVDService.apiKey} reads {@code nvd.apikey}
 * (see {@code GitHubApiClient}). A row here says <em>where to look</em>, never <em>with what
 * credential</em>, so there is nothing secret to protect at rest and nothing to rotate per row.
 *
 * <h2>{@code jobId} — the same per-invocation pointer {@code SBOM}/{@code Asset} use</h2>
 *
 * <p>{@code CONNECTOR_SYNC} is a per-invocation job type (see {@code JobType}), so — exactly like
 * {@code SBOM.jobId} and {@code Asset.jobId} — the job that is currently syncing this connector is
 * found by {@code SourceConnectorRepository#findByJobId}, not the other way around. Unlike those
 * two, nothing is "pending" on this row between the {@code POST .../sync} request and the job
 * running (there is no document to stash — the sync fetches everything itself, live, once the job
 * starts), so {@code jobId} exists purely as the lookup key.
 */
@Getter
@Setter
@Entity
@Table(name = "source_connector")
public class SourceConnector {

    /** Created, no sync has ever run. */
    public static final String STATUS_QUEUED = "QUEUED";

    /** The {@code CONNECTOR_SYNC} job is working on it. */
    public static final String STATUS_PROCESSING = "PROCESSING";

    /** The last sync finished with at least one repo ingested (or nothing to ingest at all). */
    public static final String STATUS_COMPLETED = "COMPLETED";

    /**
     * The last sync could not ingest a single repo — mirrors {@code Asset.STATUS_FAILED}'s "a
     * failed scan degrades to stale, not empty" philosophy: whatever this connector produced on an
     * earlier successful sync (its {@code Product}s and their {@code SBOM}s) is untouched, and
     * {@link #lastSyncedAt} is left at its previous value rather than cleared.
     */
    public static final String STATUS_FAILED = "FAILED";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private SourceConnectorType type;

    /** Operator-given label — "Acme org", "payments team repos" — shown in the UI, not used for lookup. */
    @Column(nullable = false, length = 255)
    private String name;

    /** GitHub org or user login to enumerate repos under. */
    @Column(nullable = false, length = 255)
    private String scope;

    /**
     * When set, sync only these {@code owner/repo} names (still restricted to {@link #scope}); when
     * empty, sync every repo the token can see under {@link #scope}. A {@code Set} rather than a
     * comma-joined column so membership checks and edits don't need string-splitting, and eager
     * because a connector's own sync (and any later read of it mid-sync) needs the full set without
     * an open Hibernate session — this collection is always small (a handful of repo names, not
     * thousands).
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "source_connector_repo_allowlist", joinColumns = @JoinColumn(name = "connector_id"))
    @Column(name = "repo_full_name", length = 255)
    @ToString.Exclude
    private Set<String> repoAllowlist = new LinkedHashSet<>();

    /** QUEUED / PROCESSING / COMPLETED / FAILED — see the constants above. Null until the first sync. */
    @Column(length = 32)
    private String status;

    /** When the last sync finished (successfully or with partial success). Null until the first one lands. */
    private LocalDateTime lastSyncedAt;

    /** The {@code CONNECTOR_SYNC} job currently (or most recently) syncing this connector. */
    private UUID jobId;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
