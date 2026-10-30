package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
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

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * The CycloneDX 1.6 {@code cryptoProperties} subset for one {@code cryptographic-asset}
 * {@link SBOMComponent} (M1g, ROADMAP.md — "M1g — CBOM ingestion"), plus its ingest-time
 * {@link QuantumVulnerabilityStatus} classification.
 *
 * <h2>Why a child table, not columns on {@code sbom_component}</h2>
 *
 * <p>~45 CBOM-only columns would bloat every plain software component row. Mirrors migration
 * {@code 021}'s {@code sbom_component_identifier} child-table precedent: cascade from the owning
 * component, tenancy inherited via {@code component.sbom}, deliberately <b>not</b> a
 * {@link TenantOwnedEntity} of its own. {@code @JsonIgnore} on {@link SBOMComponent#getCryptoAssets()}
 * keeps {@code SBOMComponent}'s existing JSON shape unchanged — {@code GET /cbom/assets} is the read
 * path for this data, not the SBOM component tree.
 *
 * <h2>Why {@code @OneToMany} + a DB unique constraint, not {@code @OneToOne}</h2>
 *
 * <p>Hibernate cannot lazy-load the inverse side of a bidirectional {@code @OneToOne} without
 * bytecode enhancement, which would add a query per {@code SBOMComponent} load everywhere — including
 * correlation, which loads every component of a scope on every scan. A one-element
 * {@code @OneToMany} list, with the true 1:1 cardinality enforced by
 * {@code uq_sbom_component_crypto_asset_component}, avoids that cost entirely.
 *
 * <p><b>{@code relatedCryptoMaterialProperties.value}</b> (real key material) is never persisted here
 * — neither as a column nor inside {@link #cryptoPropertiesJson} — see {@code CryptoPropertiesExtractor}.
 */
@Getter
@Setter
@Entity
@Table(name = "sbom_component_crypto_asset",
        uniqueConstraints = @UniqueConstraint(name = "uq_sbom_component_crypto_asset_component",
                columnNames = "component_id"))
public class SBOMComponentCryptoAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "component_id")
    @JsonIgnore
    @ToString.Exclude
    private SBOMComponent component;

    @Enumerated(EnumType.STRING)
    @Column(name = "asset_type", nullable = false, length = 32)
    private CryptoAssetType assetType;

    @Column(name = "declared_asset_type", length = 64)
    private String declaredAssetType;

    @Column(length = 255)
    private String oid;

    /** M1g's crypto-specific identity — see {@code net.jdesive.secy.model.cbom.CryptoAssetIdentity}. */
    @Column(name = "crypto_identity_key", length = 512)
    private String cryptoIdentityKey;

    @Column(length = 32)
    private String primitive;

    @Column(name = "parameter_set_identifier", length = 128)
    private String parameterSetIdentifier;

    @Column(length = 128)
    private String curve;

    @Column(name = "execution_environment", length = 64)
    private String executionEnvironment;

    @Column(name = "implementation_platform", length = 64)
    private String implementationPlatform;

    /** Comma-joined, truncated. */
    @Column(name = "certification_levels", length = 512)
    private String certificationLevels;

    @Column(name = "algorithm_mode", length = 32)
    private String algorithmMode;

    @Column(length = 32)
    private String padding;

    /** Comma-joined, truncated. */
    @Column(name = "crypto_functions", length = 512)
    private String cryptoFunctions;

    @Column(name = "classical_security_level")
    private Integer classicalSecurityLevel;

    @Column(name = "nist_quantum_security_level")
    private Integer nistQuantumSecurityLevel;

    @Column(name = "subject_name", length = 1024)
    private String subjectName;

    @Column(name = "issuer_name", length = 1024)
    private String issuerName;

    @Column(name = "not_valid_before")
    private LocalDateTime notValidBefore;

    @Column(name = "not_valid_after")
    private LocalDateTime notValidAfter;

    @Column(name = "signature_algorithm_ref", length = 255)
    private String signatureAlgorithmRef;

    @Column(name = "subject_public_key_ref", length = 255)
    private String subjectPublicKeyRef;

    @Column(name = "certificate_format", length = 64)
    private String certificateFormat;

    @Column(name = "certificate_extension", length = 64)
    private String certificateExtension;

    @Column(name = "material_type", length = 32)
    private String materialType;

    @Column(name = "material_id", length = 255)
    private String materialId;

    @Column(name = "material_state", length = 32)
    private String materialState;

    @Column(name = "algorithm_ref", length = 255)
    private String algorithmRef;

    @Column(name = "material_creation_date")
    private LocalDateTime materialCreationDate;

    @Column(name = "material_activation_date")
    private LocalDateTime materialActivationDate;

    @Column(name = "material_update_date")
    private LocalDateTime materialUpdateDate;

    @Column(name = "material_expiration_date")
    private LocalDateTime materialExpirationDate;

    @Column(name = "material_size")
    private Integer materialSize;

    @Column(name = "material_format", length = 64)
    private String materialFormat;

    @Column(name = "secured_by_mechanism", length = 64)
    private String securedByMechanism;

    @Column(name = "secured_by_algorithm_ref", length = 255)
    private String securedByAlgorithmRef;

    @Column(name = "protocol_type", length = 32)
    private String protocolType;

    @Column(name = "protocol_version", length = 64)
    private String protocolVersion;

    /** Cipher suite names only, comma-joined, truncated. */
    @Column(name = "cipher_suites", length = 4096)
    private String cipherSuites;

    /** {@code cryptoRefArray[]}, comma-joined, truncated. */
    @Column(name = "crypto_refs", length = 2048)
    private String cryptoRefs;

    @Enumerated(EnumType.STRING)
    @Column(name = "quantum_status", nullable = false, length = 16)
    private QuantumVulnerabilityStatus quantumStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "quantum_family", length = 32)
    private QuantumVulnerableFamily quantumFamily;

    @Enumerated(EnumType.STRING)
    @Column(name = "quantum_basis", length = 32)
    private QuantumClassificationBasis quantumBasis;

    @Column(name = "quantum_indicator", length = 255)
    private String quantumIndicator;

    /** Sanitized deep copy of the document's {@code cryptoProperties} — never {@code .value}. */
    @Column(name = "crypto_properties_json", columnDefinition = "text")
    private String cryptoPropertiesJson;

}
