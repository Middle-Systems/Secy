package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.CorrelatableComponent;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@Entity
@Transactional
@Table(name = "sbom_component")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOMComponent implements CorrelatableComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String type;

    private String bomRef;

    private String name;

    /**
     * The version this SBOM declared. <b>Mutable across SBOM versions</b> — a component upgraded from
     * 4.17.20 to 4.17.21 keeps its {@link #identityKey} and changes this.
     */
    private String version;

    @Column(length = 1024)
    private String description;

    @Column(length = 512)
    private String purl;

    /**
     * The organization that supplied this component instance (M1h) — CycloneDX
     * {@code component.supplier.name}, SPDX {@code PackageSupplier} with its
     * {@code Organization:}/{@code Person:} prefix stripped. Null when the document declared none.
     * Feeds {@code SbomQualityScorer}'s {@code SUPPLIER} coverage test.
     */
    @Column(name = "supplier_name", length = 255)
    private String supplierName;

    /**
     * Stable identity of this component within its product, across SBOM versions.
     *
     * <p>The version-less PURL ({@code maven/org.apache.logging.log4j:log4j-core}), or
     * {@code name/<lowercased name>} when the document declared no usable PURL. This — not
     * {@link #id}, which is fresh on every upload — is what
     * {@code CorrelationService} keys the alert upsert on, so re-uploading a product's SBOM revives
     * and auto-resolves its existing alerts instead of orphaning them and raising a new set.
     *
     * <p>Derived, never assigned by callers: {@link #refreshIdentityKey()} recomputes it on every
     * insert and update from {@link #purl} and {@link #name}, so no code path can create a component
     * without one and the column can never drift from the fields it is derived from.
     *
     * <p>Nullable only for a component with neither a PURL nor a name, which cannot be carried
     * forward at all; correlation falls back to the row id for those.
     *
     * @see net.jdesive.secy.model.component.ComponentIdentity
     */
    @Column(name = "identity_key", length = ComponentIdentity.MAX_LENGTH)
    private String identityKey;

    /**
     * Digests the document declared for this component — CycloneDX {@code hashes[]} / SPDX
     * {@code checksums[]}. Empty for the large majority of SBOMs, which omit them.
     *
     * <p>Phase 6 reads the SHA-256 entry against the malware-hash corpus. See
     * {@link ComponentHash} for why the whole set is stored rather than one column.
     */
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "sbom_component_hash",
            joinColumns = @JoinColumn(name = "component_id"),
            indexes = @Index(name = "idx_sbom_component_hash_value", columnList = "hash_value"))
    @ToString.Exclude
    private Set<ComponentHash> hashes = new LinkedHashSet<>();

    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMLicense> licenses = new ArrayList<>();

    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<SBOMReference> references = new ArrayList<>();

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private SBOM sbom;

    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<VulnerabilityAlert> vulnerabilityAlerts;

    /**
     * Declared CPE/SWID identifiers for this component instance (M1c). {@code @JsonIgnore}d —
     * {@code open-in-view} would otherwise turn every serialized {@code SBOMComponent} (this SBOM's
     * tree, every alert's {@code component}) into an N+1; {@code ComponentIdentityService#describe}
     * is the read path for these.
     *
     * @see SBOMComponentIdentifier
     */
    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    @ToString.Exclude
    private List<SBOMComponentIdentifier> identifiers = new ArrayList<>();

    /**
     * Detected disagreements between this component's declared identifiers and its primary identity,
     * or with another component's content digest (M1c). Same {@code @JsonIgnore} reasoning as
     * {@link #identifiers}.
     *
     * @see SBOMComponentIdentityConflict
     */
    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    @ToString.Exclude
    private List<SBOMComponentIdentityConflict> identityConflicts = new ArrayList<>();

    /**
     * Whether this component's own declared secondary identifiers corroborate, say nothing about, or
     * conflict with its {@link #identityKey} (M1c). Computed by {@code ComponentIdentityService}/
     * {@code SBOMService} at ingest — <b>deliberately NOT in {@code @PrePersist}/{@code @PreUpdate}</b>,
     * unlike {@link #identityKey}: the cross-instance hash-collision pass
     * ({@code ComponentIdentityService#flagHashIdentityCollisions}) sets this to {@code CONFLICTING}
     * on already-persisted rows (including rows outside the current SBOM, via a bulk update), and a
     * lifecycle callback re-deriving it on the next flush/update would silently overwrite that later
     * verdict. {@code null} means "not assessed" — see {@link IdentityConfidence}'s Javadoc for the
     * orthogonality note versus {@link MatchConfidence}.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "identity_confidence", length = 16)
    private IdentityConfidence identityConfidence;

    /**
     * How far this component sits from the product's root in the document's own dependency graph
     * (M1l) — null means "not assessed" (a pre-M1l row, or a component built directly by a test/
     * scanner path that never goes through {@code SBOMService#ingestDocument}). Set explicitly by
     * {@code SBOMService}, deliberately NOT in {@code @PrePersist}/{@code @PreUpdate} — same
     * reasoning as {@link #identityConfidence}: the classification is computed once from the whole
     * document's edge graph, not re-derivable from this one row on every flush.
     *
     * @see net.jdesive.secy.model.component.DependencyGraphAnalyzer
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "dependency_depth", length = 16)
    private DependencyDepth dependencyDepth;

    /**
     * Hop distance from the product root to this component (1 = direct) — null unless {@link
     * #dependencyDepth} is {@code DIRECT}/{@code TRANSITIVE} (M1l).
     */
    @Column(name = "dependency_distance")
    private Integer dependencyDistance;

    /**
     * One representative shortest path from the product root to this component, as a JSON array of
     * bom-refs (root first, this component's own ref last) — null when {@link #dependencyDepth} is
     * {@code UNKNOWN}/not assessed, or when the path exceeds {@code
     * DependencyGraphAnalyzer#MAX_PATH_HOPS} hops (M1l). {@code @JsonIgnore}d — exposed only via
     * {@code GET /actionable/{id}}'s {@code dependency} block, to avoid double-encoded JSON reaching
     * the UI through this entity's own serialization.
     */
    @Column(name = "dependency_path", columnDefinition = "text")
    @JsonIgnore
    private String dependencyPath;

    /**
     * The CycloneDX 1.6 {@code cryptoProperties} row for this component, when it is a
     * {@code cryptographic-asset} on a document that supports CBOM (M1g) — at most one, enforced by
     * {@code uq_sbom_component_crypto_asset_component}. Read path is {@code GET /cbom/assets}, not
     * this collection — {@code @JsonIgnore}d for the same N+1 reason as {@link #identifiers}.
     *
     * @see SBOMComponentCryptoAsset
     */
    @OneToMany(mappedBy = "component", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    @ToString.Exclude
    private List<SBOMComponentCryptoAsset> cryptoAssets = new ArrayList<>();

    /**
     * Keep {@link #identityKey} in lockstep with the fields it is derived from.
     *
     * <p>On the entity rather than in {@code SBOMService} on purpose: the golden-set fixtures, the
     * Phase 4 scanner path and anything else that builds a component directly all get a correct key
     * for free, and correlation's upsert can never be defeated by a caller that forgot to set it.
     */
    @PrePersist
    @PreUpdate
    void refreshIdentityKey() {
        this.identityKey = ComponentIdentity.keyOf(this.purl, this.name);
    }

}
