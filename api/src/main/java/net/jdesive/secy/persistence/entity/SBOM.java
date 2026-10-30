package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Entity
@Transactional
@Table(name = "sbom")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOM extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String format;

    private String specVersion;

    private int version;

    private String productVersion;

    private boolean active;

    private String status;

    private LocalDateTime lastScannedAt;

    private LocalDateTime uploadDate = LocalDateTime.now();

    /**
     * Raw JSON body of the upload, held only until the {@code SBOM_UPLOAD} job that owns this row
     * (see {@link #jobId}) consumes it — {@code SBOMService.ingestUploadJob} re-parses it and then
     * clears the column. Null once ingested (or for any SBOM predating Phase 3's job queue). Never
     * serialized: a multi-MB SBOM would otherwise ride along on every {@code GET /products}.
     */
    @Column(columnDefinition = "text")
    @JsonIgnore
    private String pendingRawBody;

    /**
     * The {@code SBOM_UPLOAD} job ingesting this row, set when the placeholder is created. A
     * generic {@link Job} row carries no payload of its own (every other job type is a stateless
     * singleton feed pull), so this is the pointer the job uses to find "which SBOM am I for" —
     * see {@code SBOMRepository#findByJobId}.
     */
    private UUID jobId;

    /** Which channel this SBOM arrived through (M1c). Null on any row that predates M1c. */
    @Enumerated(EnumType.STRING)
    @Column(name = "ingestion_source", length = 32)
    private SbomIngestionSource ingestionSource;

    /**
     * The {@link SourceConnector} that produced this SBOM, when {@link #ingestionSource} is
     * {@link SbomIngestionSource#GITHUB_CONNECTOR} — a plain id, not a {@code @ManyToOne}, so
     * serializing an {@code SBOM} never drags a connector's config along and no on-delete behavior
     * needs modelling in the entity graph (the FK itself is {@code on delete set null}, migration
     * {@code 021c}).
     */
    @Column(name = "source_connector_id")
    private UUID sourceConnectorId;

    /**
     * Where in the SDLC this SBOM was captured. <b>M1e populates this; nothing in M1c writes it.</b>
     * {@code null} means "stage unknown", not a default stage.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_stage", length = 16)
    private SbomLifecycleStage lifecycleStage;

    /**
     * The document's own declared creation time (M1h) — CycloneDX {@code metadata.timestamp}, SPDX
     * {@code creationInfo.created} — never {@link #uploadDate} (Secy's own ingest time). Null when
     * the document declared none or it was unparseable.
     */
    @Column(name = "document_timestamp")
    private LocalDateTime documentTimestamp;

    /**
     * Who created the SBOM DATA (M1h), joined {@code "; "} — CycloneDX {@code metadata.authors[]}/
     * 1.6 {@code metadata.manufacturer}, SPDX {@code Person:}/{@code Organization:} creators. Tools
     * never count. Null when the document declared none.
     */
    @Column(name = "document_authors", length = 1024)
    private String documentAuthors;

    /**
     * This document's NTIA minimum-elements completeness score (M1h), or null when it was not
     * scored (no non-crypto components). See {@code SbomQualityScorer}.
     */
    @Embedded
    private SbomQualityScore quality;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMTool> tools = new ArrayList<>();

    @OneToOne(cascade = CascadeType.ALL)
    private SBOMComponent component;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMComponent> components = new ArrayList<>();

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private Product product;

    // This creates a virtual field in your JSON
    @JsonProperty("totalVulnerabilities")
    public int getTotalVulnerabilities() {
        if (components == null) return 0;
        return components.stream()
                .mapToInt(c -> c.getVulnerabilityAlerts() != null ? c.getVulnerabilityAlerts().size() : 0)
                .sum();
    }

}
