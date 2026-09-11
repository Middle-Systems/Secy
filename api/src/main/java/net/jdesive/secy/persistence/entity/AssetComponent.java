package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.CorrelatableComponent;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One package a scanner found on an {@link Asset} — the asset-side twin of {@code SBOMComponent}.
 *
 * <h2>Rows are upserted, never replaced</h2>
 *
 * <p>An SBOM upload writes fresh {@code sbom_component} rows every time, because an SBOM version is a
 * snapshot of what a product shipped at one moment and the history of those snapshots is the point.
 * An asset has no such versioning: there is one current image, re-scanned. So the scan upserts on
 * {@code (asset_id, identity_key)} instead.
 *
 * <p>Components that disappear from a later scan are <b>not deleted</b> — {@link #presentInLastScan}
 * goes false. Deleting them would take the {@code vulnerability_alert} rows that cite them with it,
 * which is precisely the "never silently delete evidence" rule Phase 2 set for alerts. A row that is
 * absent from the last scan stops being correlated, so its alerts auto-resolve, and
 * {@link #lastSeenAt} records when it was last actually observed.
 */
@Getter
@Setter
@Entity
@Table(name = "asset_component",
        uniqueConstraints = @UniqueConstraint(name = "uq_asset_component_identity",
                columnNames = {"asset_id", "identity_key"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class AssetComponent implements CorrelatableComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @ToString.Exclude
    @JsonIgnore
    private Asset asset;

    @Column(length = 512)
    private String name;

    @Column(length = 255)
    private String version;

    @Column(length = 512)
    private String purl;

    /** OSV ecosystem derived from {@link #purl}, or null for an OS package / declared CPE. */
    @Column(length = 64)
    private String ecosystem;

    /**
     * Stable identity within this asset, across re-scans — the version-less PURL, or
     * {@code name/<lowercased name>} for a package with no PURL (which is every OS package).
     *
     * <p>Spelled by the same {@link ComponentIdentity#keyOf} an {@code SBOMComponent} uses, and
     * derived on persist for the same reason: no writer can create a row without one, and the column
     * can never drift from the fields it comes from.
     */
    @Column(name = "identity_key", length = ComponentIdentity.MAX_LENGTH)
    private String identityKey;

    /** Which scanner reported it, or {@code DECLARED_CPE}. Provenance only. */
    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private AssetComponentSource source;

    /** The scanner's own target for this package — Trivy {@code Results[].Target}, Grype's source. */
    @Column(length = 512)
    private String scanTarget;

    /** Trivy {@code PkgPath} / Grype {@code locations[0].path} — where in the image it lives. */
    @Column(length = 1024)
    private String packagePath;

    /** Trivy {@code Layer.DiffID} / Grype {@code locations[0].layerID} — which layer introduced it. */
    @Column(length = 255)
    private String layer;

    /**
     * Whether the most recent scan of this asset still reported the package. False rows are kept as
     * evidence but are not correlated, so their alerts auto-resolve. See the class note.
     */
    @Column(name = "present_in_last_scan", nullable = false)
    private boolean presentInLastScan = true;

    /** When a scan last reported this package. */
    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    /** See {@code SBOMComponent.refreshIdentityKey()} — same contract, same reason it lives here. */
    @PrePersist
    @PreUpdate
    void refreshIdentityKey() {
        this.identityKey = ComponentIdentity.keyOf(this.purl, this.name);
    }

}
