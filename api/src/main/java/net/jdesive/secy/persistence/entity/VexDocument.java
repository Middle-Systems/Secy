package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One uploaded VEX document (OpenVEX / CSAF 2.0 subset / CycloneDX VEX) — ROADMAP.md, M1f "VEX
 * ingestion". Never deleted: a superseded or manually deactivated document keeps its row, flagged
 * {@link #active} false, so history and provenance survive (the M1c/M1e "flag, don't delete"
 * discipline).
 *
 * <p>Parsing runs synchronously in {@code POST /vex} before anything is persisted — see
 * {@code VexController}. This placeholder row is written once the document has already been
 * validated and parsed, carrying the raw body until the {@code VEX_UPLOAD} job actually persists
 * {@link VexStatement} rows from it (see {@code VexIngestionService}).
 */
@Getter
@Setter
@Entity
@Table(name = "vex_document")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class VexDocument extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VexDocumentFormat format;

    @Column(name = "spec_version", length = 32)
    private String specVersion;

    /**
     * Per-format document identity used for supersession (see {@code VexIngestionService}):
     * OpenVEX {@code @id}, CSAF {@code publisher.namespace + "#" + tracking.id}, CycloneDX
     * {@code serialNumber}. Falls back to {@code "sha256:" + contentSha256} when the document itself
     * declares none.
     */
    @Column(name = "document_key", nullable = false, length = 1024)
    private String documentKey;

    @Column(name = "document_version", length = 64)
    private String documentVersion;

    @Column(length = 512)
    private String author;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VexOrigin origin;

    /** Embedded-CycloneDX-VEX product scope, when the document is an SBOM that also carries {@code vulnerabilities[]}. */
    @Column(name = "scope_product_id")
    private UUID scopeProductId;

    @Column(name = "document_timestamp")
    private LocalDateTime documentTimestamp;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VexDocumentStatus status;

    /** The {@code VEX_UPLOAD} job ingesting this document. */
    @Column(name = "job_id")
    private UUID jobId;

    /**
     * The raw uploaded body, held only until the {@code VEX_UPLOAD} job re-parses and persists it as
     * {@link VexStatement} rows, then cleared. Never serialized — object storage of the original
     * document is Packaging-milestone territory, not this one; only {@link #contentSha256} is kept
     * long-term.
     */
    @JsonIgnore
    @Column(name = "pending_raw_body", columnDefinition = "text")
    private String pendingRawBody;

    @Column(name = "content_sha256", nullable = false, length = 64)
    private String contentSha256;

    @Column(nullable = false)
    private boolean active;

    /** The document that superseded this one (same tenant/format/documentKey/origin/scope), if any. */
    @Column(name = "superseded_by_id")
    private UUID supersededById;

    @Column(name = "statement_count", nullable = false)
    private int statementCount;

    @Column(name = "skipped_count", nullable = false)
    private int skippedCount;

    /** Newline-joined parser warnings, first 50, truncated to fit. */
    @Column(length = 4096)
    private String warnings;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    @Column(name = "processed_at")
    private LocalDateTime processedAt;

    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;

    @PrePersist
    protected void onCreate() {
        if (this.uploadedAt == null) {
            this.uploadedAt = LocalDateTime.now();
        }
    }

}
