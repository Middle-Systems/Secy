package net.jdesive.secy.persistence.entity;

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
 * One (document, CVE, target) VEX assertion — ROADMAP.md, M1f "VEX ingestion". Never deleted: a
 * superseded or deactivated document's statements are bulk-flagged {@link #active} false, same
 * discipline as {@link VexDocument}.
 *
 * <p>Document-level fields ({@link #format}, {@link #origin}, {@link #scopeProductId},
 * {@link #author}) are copied onto every statement rather than joined at resolution time, so
 * {@code VexResolutionService} can resolve with a single-table query over
 * {@code vex_statement(tenant_id, cve_id)} — see migration {@code 024c}'s partial index.
 */
@Getter
@Setter
@Entity
@Table(name = "vex_statement")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class VexStatement extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "document_id", nullable = false)
    private UUID documentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VexDocumentFormat format;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VexOrigin origin;

    @Column(name = "scope_product_id")
    private UUID scopeProductId;

    @Column(length = 512)
    private String author;

    /**
     * {@code lower(trim(author))} when the document declared a non-blank author, else
     * {@code "document:" + documentKey} — the grouping key {@code VexResolver} supersedes statements
     * within, so two statements with no declared author still supersede each other by document
     * rather than being treated as two independent "authors".
     */
    @Column(name = "author_key", nullable = false, length = 1024)
    private String authorKey;

    /** Mirrors the owning document's {@code active}; flipped in bulk on supersession/deactivation. */
    @Column(nullable = false)
    private boolean active;

    @Column(name = "cve_id", nullable = false, length = 64)
    private String cveId;

    /** Comma-joined aliases the source document listed alongside the primary CVE id. */
    @Column(name = "vulnerability_aliases", length = 1024)
    private String vulnerabilityAliases;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private VexStatus status;

    /** The native status value verbatim, before normalization onto {@link #status}. */
    @Column(name = "source_status", nullable = false, length = 64)
    private String sourceStatus;

    @Enumerated(EnumType.STRING)
    @Column(length = 64)
    private VexJustification justification;

    /** The native justification value verbatim, before normalization onto {@link #justification}. */
    @Column(name = "source_justification", length = 128)
    private String sourceJustification;

    @Column(name = "impact_statement", length = 4096)
    private String impactStatement;

    @Column(name = "action_statement", length = 4096)
    private String actionStatement;

    /** The document's own reference to the target, verbatim — a bom-ref, product_id, or PURL. */
    @Column(name = "product_ref", nullable = false, length = 1024)
    private String productRef;

    @Column(name = "target_purl", length = 1024)
    private String targetPurl;

    /** Informational only — never used for matching (M1f is PURL-only; see {@code VexResolver}). */
    @Column(name = "target_cpe", length = 1024)
    private String targetCpe;

    /**
     * {@code ComponentIdentity.keyOf(targetPurl, null)} — null means this statement can never match
     * any alert (an unresolvable product reference, a CPE-only target, etc.), and it is still stored,
     * flagged with a parser warning, rather than dropped.
     */
    @Column(name = "match_key", length = 512)
    private String matchKey;

    /** Null means "all versions of {@link #matchKey}"; non-null pins to that exact version string. */
    @Column(name = "match_version", length = 255)
    private String matchVersion;

    @Column(name = "statement_timestamp", nullable = false)
    private LocalDateTime statementTimestamp;

    /** Position within the source document — supersession/explain tie-break, and traceability. */
    @Column(nullable = false)
    private int ordinal;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
