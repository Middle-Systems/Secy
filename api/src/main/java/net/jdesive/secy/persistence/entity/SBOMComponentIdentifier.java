package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

/**
 * One declared CPE or SWID identifier for one {@link SBOMComponent} instance (M1c, ROADMAP.md —
 * "Canonical component identity") — the document field it came from is {@link #source}, so a UI or
 * a future re-assessment can tell a CycloneDX {@code component.cpe} from an SPDX
 * {@code externalRefs[].cpe23Type} without re-parsing the original document.
 *
 * <p>SBOM-only in M1c; the asset-side equivalent is a future M3 table.
 *
 * <p>Does <b>not</b> extend {@link TenantOwnedEntity} — tenancy is inherited through
 * {@link #component}'s {@code sbom}, the same choice already made for {@link ComponentHash}.
 *
 * <p>Never feeds {@link SBOMComponent#getIdentityKey()} — see {@code ComponentIdentity}'s "Secondary
 * identifiers" note.
 */
@Getter
@Setter
@Entity
@Table(name = "sbom_component_identifier",
        uniqueConstraints = @UniqueConstraint(name = "uq_sbom_component_identifier",
                columnNames = {"component_id", "identifier_type", "identifier_value"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOMComponentIdentifier {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "component_id")
    @JsonIgnore
    @ToString.Exclude
    private SBOMComponent component;

    @Enumerated(EnumType.STRING)
    @Column(name = "identifier_type", nullable = false, length = 16)
    private SecondaryIdentifierType identifierType;

    /** Verbatim value (CPE lower-cased at parse time; SWID tagId case-preserved). Never truncated on write — over-long values are dropped upstream. */
    @Column(name = "identifier_value", nullable = false, length = 1024)
    private String identifierValue;

    @Column(name = "declared_name", length = 255)
    private String declaredName;

    @Column(name = "declared_version", length = 255)
    private String declaredVersion;

    /** The exact document field this came from, e.g. {@code cyclonedx:component.cpe} — see {@code SecondaryIdentifiers}. */
    @Column(nullable = false, length = 64)
    private String source;

}
