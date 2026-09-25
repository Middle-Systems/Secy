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
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * "The downstream stage has something the upstream stage never vouched for" — one detected
 * disagreement between an adjacent pair of a product's lifecycle-stage SBOMs (M1e, ROADMAP.md —
 * "SBOM lifecycle stages + diffing"). See {@code LifecycleDiffer} for exactly how a row here is
 * derived, and {@code LifecycleDiffService} for how it is reconciled on every relevant SBOM upload.
 *
 * <h2>Why its own table, not {@code VulnerabilityAlert} or an M1j {@code Finding}</h2>
 *
 * <p>A drift finding has no CVE and never will — it is a structural disagreement between two SBOMs,
 * not a vulnerability match — so it does not belong in {@code vulnerability_alert}, for exactly the
 * reason {@link CompromiseFinding}'s Javadoc gives for its own table. And M1j's planned {@code Finding}
 * supertype does not exist yet; this is purpose-built now and M1j folds it in later, not the reverse.
 *
 * <h2>Why plain UUID references, not {@code @ManyToOne}</h2>
 *
 * <p>Follows M1c's {@code SBOM.sourceConnectorId} precedent: a JPA association here would create H2
 * foreign keys that break every {@code sbomRepository.deleteAll()}/{@code productRepository.deleteAll()}
 * {@code @BeforeEach} across the shared test suite whenever a drift row is left behind from another
 * test class. PostgreSQL still gets real foreign keys in the migration (cascade/set-null).
 *
 * <h2>What is deliberately NOT here</h2>
 *
 * <p>No {@code triage_state}/{@code assignee_id}/{@code snoozed_until}/{@code severity} — those are
 * M1j (triage consolidation) and M1i (scoring) territory. {@link #stagePair}'s
 * {@link LifecycleStagePair#category()} gives them what they will need later. Not surfaced on
 * {@code GET /actionable} either — see {@code LifecycleDriftController}'s Javadoc.
 */
@Getter
@Setter
@Entity
@Table(name = "lifecycle_drift_finding",
        uniqueConstraints = @UniqueConstraint(name = "uq_lifecycle_drift_finding_key",
                columnNames = {"product_id", "stage_pair", "drift_kind", "identity_key"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class LifecycleDriftFinding extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "product_id", nullable = false)
    private UUID productId;

    @Enumerated(EnumType.STRING)
    @Column(name = "stage_pair", nullable = false, length = 32)
    private LifecycleStagePair stagePair;

    @Enumerated(EnumType.STRING)
    @Column(name = "drift_kind", nullable = false, length = 32)
    private LifecycleDriftKind driftKind;

    /** The component identity (see {@code ComponentIdentity}) this finding is about. */
    @Column(name = "identity_key", nullable = false, length = 512)
    private String identityKey;

    @Column(name = "component_name", length = 255)
    private String componentName;

    @Column(name = "component_purl", length = 512)
    private String componentPurl;

    /** Distinct, sorted, comma-joined concrete versions seen in the observed (downstream) SBOM. */
    @Column(name = "observed_version", length = 255)
    private String observedVersion;

    /** Same shape as {@link #observedVersion}, from the baseline SBOM. Null for {@code UNEXPECTED_COMPONENT}. */
    @Column(name = "baseline_version", length = 255)
    private String baselineVersion;

    /** The upstream SBOM in this pair — {@link LifecycleStagePair#baseline()}'s stage. */
    @Column(name = "baseline_sbom_id", nullable = false)
    private UUID baselineSbomId;

    /** The downstream SBOM in this pair — {@link LifecycleStagePair#observed()}'s stage. */
    @Column(name = "observed_sbom_id", nullable = false)
    private UUID observedSbomId;

    /** The representative {@code sbom_component} row in the observed SBOM, when one still exists. */
    @Column(name = "observed_component_id")
    private UUID observedComponentId;

    @Column(nullable = false, length = 1024)
    private String summary;

    /**
     * Whether the most recent diff run for this pair still reproduced this disagreement. Reconciled
     * exactly like {@link VulnerabilityAlert}/{@link CompromiseFinding}: never deleted, revived if the
     * disagreement returns.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_state", nullable = false, length = 16)
    private AlertLifecycleState lifecycleState = AlertLifecycleState.ACTIVE;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
