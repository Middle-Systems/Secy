package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * One CIS/Docker benchmark audit of one {@link Asset}, as uploaded.
 *
 * <h2>A report is a dated snapshot, not a mutable inventory (Phase 5)</h2>
 *
 * <p>Deliberately the {@code SBOM} model rather than the {@code Asset} model: every upload creates a
 * new row. A compliance report is an audit artefact with a date on it — "on the 3rd, 41 of 116
 * controls failed" — and the whole value of keeping them is the trend. Upserting one report row per
 * asset would destroy exactly the history the Compliance view exists to show.
 *
 * <p>Its <b>vulnerability half is not stored that way</b>. Those findings become
 * {@link AssetComponent}s and {@link VulnerabilityAlert}s on {@link #asset}, reconciled in place by
 * {@code CorrelationService} exactly as an {@code ASSET_SCAN} would — so re-uploading a report for
 * the same asset updates its alerts rather than duplicating them, and the alerts reach
 * {@code GET /actionable}. The rows under {@link #vulnerabilities} are kept only as the report's own
 * evidence of what it said, and as the input a re-scan replays.
 */
@Getter
@Setter
@Entity
@Table(name = "docker_compliance_report")
public class DockerComplianceReport {

    /** Uploaded and validated; the {@code COMPLIANCE_SCAN} job has not started. Mirrors {@code Asset}. */
    public static final String STATUS_QUEUED = "QUEUED";

    /** The job is parsing/persisting/correlating it. */
    public static final String STATUS_PROCESSING = "PROCESSING";

    /** The report is stored and its vulnerability half has been correlated. */
    public static final String STATUS_COMPLETED = "COMPLETED";

    /** The job threw. Whatever the report had already written stays; scan it again to retry. */
    public static final String STATUS_FAILED = "FAILED";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** The benchmark's own id, e.g. {@code docker-cis-1.6.0}. Not unique: every audit repeats it. */
    private String reportId;

    private String title;

    @Column(length = 4096)
    private String description;

    private String version;

    /**
     * What was audited. Never null in practice — the upload refuses a report it cannot name an asset
     * for, because a compliance report with no subject is unreadable.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonIgnore
    private Asset asset;

    /** QUEUED / PROCESSING / COMPLETED / FAILED — see the constants above. */
    @Column(length = 32)
    private String status;

    /**
     * Raw uploaded JSON, held only until the {@code COMPLIANCE_SCAN} job that owns this row consumes
     * it. The {@code SBOM.pendingRawBody} / {@code Asset.pendingRawBody} pattern, for the same
     * reason: the generic {@code Job} row has no payload column.
     */
    @Column(columnDefinition = "text")
    @JsonIgnore
    private String pendingRawBody;

    /** The {@code COMPLIANCE_SCAN} job ingesting or re-scanning this row. */
    private UUID jobId;

    /** Controls satisfied, violated and not evaluated — the detail view's pass/fail summary. */
    @Column(name = "passed_controls", nullable = false)
    private int passedControls;

    @Column(name = "failed_controls", nullable = false)
    private int failedControls;

    @Column(name = "skipped_controls", nullable = false)
    private int skippedControls;

    /** When the last scan of this report finished correlating. */
    private LocalDateTime scannedAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerComplianceReportReference> references = new ArrayList<>();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerComplianceControl> controls = new ArrayList<>();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerComplianceReportMisconfig> misconfigurations = new ArrayList<>();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<DockerComplianceReportVulnerability> vulnerabilities = new ArrayList<>();

    /** Controls the benchmark actually contained. */
    public int getTotalControls() {
        return passedControls + failedControls + skippedControls;
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
