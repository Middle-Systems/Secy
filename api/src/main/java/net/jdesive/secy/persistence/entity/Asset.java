package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * One piece of infrastructure Secy knows about: a container image, a host, or a service.
 *
 * <h2>An asset is not "part of" a product</h2>
 *
 * <p>{@link #product} is nullable and stays that way. A product is something you <em>ship</em> and
 * an SBOM describes it; an asset is something you <em>run</em>, and plenty of what you run
 * (a base image, a build agent, a database host) belongs to no catalogued product at all. When the
 * link is set it is a convenience for filtering and reporting — it does not make the asset's
 * components part of the product's inventory, and it does not merge their alert scopes. See
 * {@code CorrelationService} for why the scopes stay separate.
 *
 * <h2>Re-scanning updates in place</h2>
 *
 * <p>An asset is keyed by {@code (type, name)}: scanning {@code acme/api:1.4.2} again finds the same
 * row, upserts its components by identity, and reconciles its alerts — the same lifecycle an SBOM
 * re-upload gets. That is the whole reason {@code AssetComponent} carries an identity key.
 */
@Getter
@Setter
@Entity
@Table(name = "asset",
        uniqueConstraints = @UniqueConstraint(name = "uq_asset_type_name", columnNames = {"type", "name"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Asset {

    /** A scan that has been accepted but not yet ingested. Mirrors {@code SBOM.status}. */
    public static final String STATUS_QUEUED = "QUEUED";

    /** The {@code ASSET_SCAN} job is working on it. */
    public static final String STATUS_PROCESSING = "PROCESSING";

    /** The last scan ingested cleanly. */
    public static final String STATUS_COMPLETED = "COMPLETED";

    /**
     * The last scan job threw. The asset, its components and its alerts from the previous successful
     * scan are all still there — a failed scan is recoverable by scanning again, never a data loss.
     */
    public static final String STATUS_FAILED = "FAILED";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AssetType type;

    /** Image {@code repository:tag}, hostname, or service name — whatever identifies it to an operator. */
    @Column(nullable = false, length = 512)
    private String name;

    /** Optional link to a catalogued product. See the class note: an asset need not have one. */
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonIgnoreProperties({"sboms"})
    private Product product;

    /** When the last scan of this asset finished ingesting. Null until the first one succeeds. */
    private LocalDateTime lastScannedAt;

    /** QUEUED / PROCESSING / COMPLETED / FAILED — see the constants above. */
    @Column(length = 32)
    private String status;

    /** Which scanner produced the last accepted scan, for the "scan output" provenance line in the UI. */
    @Column(length = 32)
    private String scanner;

    /**
     * CPEs the operator declared for this asset, for the OS/firmware/appliance case no package
     * manager enumerates. Each becomes a {@link AssetComponentSource#DECLARED_CPE} component on
     * ingest, so it flows through the same CPE fallback path an unPURLed OS package already takes.
     */
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "asset_declared_cpe", joinColumns = @JoinColumn(name = "asset_id"))
    @Column(name = "cpe", length = 512)
    @ToString.Exclude
    private Set<String> declaredCpes = new LinkedHashSet<>();

    /**
     * Raw scanner JSON, held only until the {@code ASSET_SCAN} job that owns this row consumes it —
     * exactly the {@code SBOM.pendingRawBody} pattern, and for the same reason: the generic
     * {@link Job} row has no payload column. Never serialized.
     */
    @Column(columnDefinition = "text")
    @JsonIgnore
    private String pendingRawBody;

    /** Which scan format {@link #pendingRawBody} is, so the job re-parses it the same way. */
    @Column(length = 16)
    @JsonIgnore
    private String pendingScanFormat;

    /** The {@code ASSET_SCAN} job ingesting this row. See {@code AssetRepository#findByJobId}. */
    private UUID jobId;

    @OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnore
    private List<AssetComponent> components = new ArrayList<>();

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
