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
import java.util.List;
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
