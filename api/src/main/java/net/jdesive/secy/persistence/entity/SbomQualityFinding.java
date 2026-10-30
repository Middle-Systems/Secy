package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
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
 * "The SBOM currently feeding this product slot is too incomplete to trust" — one low-scoring
 * (below {@code SbomQualityScorer.FINDING_THRESHOLD}) SBOM per (product, lifecycle-stage slot), or
 * per bucket (Unassigned) SBOM (M1h, ROADMAP.md — "M1h — SBOM quality scoring"). See
 * {@code SbomQualityScorer} for how the embedded score is computed and
 * {@code SbomQualityFindingService} for how a row here is reconciled on every relevant SBOM upload.
 *
 * <h2>Why its own table, not {@code VulnerabilityAlert}</h2>
 *
 * <p>A quality finding has no CVE and never will — it is a structural property of one document's
 * completeness, not a vulnerability match — so it does not belong in {@code vulnerability_alert},
 * for the same reason {@link CompromiseFinding}/{@link LifecycleDriftFinding}/
 * {@link QuantumVulnerabilityFinding} have their own tables.
 *
 * <h2>Why identity is the SLOT, not the SBOM</h2>
 *
 * <p>The {@link SbomQualityScore} embedded on {@link SBOM} answers "how complete is this one
 * document"; this finding answers a different question — "the SBOM feeding product P's stage S is
 * low quality", an ongoing pipeline problem. If this were keyed per-SBOM-id, every re-upload of an
 * equally-poor SBOM would auto-resolve the old finding and raise a fresh one, losing the continuity
 * an operator's triage on it. Identity is {@code (product_id, lifecycle_stage)} for a normal
 * product — null stage is the legacy unstaged slot, exactly matching M1e's active-slot key — or
 * {@code scope_sbom_id} for the Unassigned bucket, one finding per bucket SBOM (bucket SBOMs are
 * unrelated documents that never supersede each other, M1g's precedent). Re-uploading an improved
 * SBOM to the same slot auto-resolves this row; a later poor upload revives the same row to
 * {@code ACTIVE} rather than raising a new one.
 *
 * <h2>Why plain UUID references, not {@code @ManyToOne}</h2>
 *
 * <p>Follows {@link QuantumVulnerabilityFinding}'s precedent: a JPA association here would create H2
 * foreign keys that break every {@code *Repository.deleteAll()} {@code @BeforeEach} across the
 * shared test suite whenever a finding row is left behind from another test class. PostgreSQL still
 * gets real foreign keys in the migration (cascade on delete).
 *
 * <h2>No entity-level unique constraint</h2>
 *
 * <p>Uniqueness is the migration's two partial/expression indexes — one on
 * {@code (product_id, coalesce(lifecycle_stage, 'UNSTAGED')) WHERE scope_sbom_id IS NULL}, one on
 * {@code (scope_sbom_id) WHERE scope_sbom_id IS NOT NULL} — which JPA's {@code @UniqueConstraint}
 * cannot express (no partial/expression index support). {@code SbomQualityFindingService} enforces
 * the same key in memory.
 *
 * <h2>What is deliberately NOT here</h2>
 *
 * <p>Still no {@code triage_state}/{@code assignee_id}/{@code snoozed_until}/severity band on this
 * table — same M1j (ROADMAP.md — "Finding &amp; Action-item model") satellite resolution as
 * {@link QuantumVulnerabilityFinding}: resolved via
 * {@code net.jdesive.secy.service.finding.FindingResolver} into a {@code ResolvedFinding}, triaged/
 * grouped only through the separate {@code action_item}/{@code action_item_finding} tables, never by
 * a column added here. Scoring is still not done for this finding type and, as of M1j, is
 * <b>unowned</b> — no milestone currently promises it. Not surfaced on {@code GET /actionable}
 * either — no KEV/EPSS/CVSS to rank it by, same reasoning as
 * {@code LifecycleDriftController}/{@code CbomController}.
 */
@Getter
@Setter
@Entity
@Table(name = "sbom_quality_finding")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SbomQualityFinding extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "product_id", nullable = false)
    private UUID productId;

    /** Non-null for a bucket (Unassigned) SBOM's finding — see {@code SbomQualityFindingService}. */
    @Column(name = "scope_sbom_id")
    private UUID scopeSbomId;

    /** Null for the legacy unstaged slot, matching M1e's active-slot key. */
    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_stage", length = 16)
    private SbomLifecycleStage lifecycleStage;

    /** The SBOM that most recently determined this finding's state. */
    @Column(name = "sbom_id", nullable = false)
    private UUID sbomId;

    /** A snapshot of the last low score seen for this slot — never overwritten by a later good score. */
    @Embedded
    private SbomQualityScore quality;

    @Column(name = "score_threshold", nullable = false)
    private Integer scoreThreshold;

    @Column(name = "missing_elements", length = 255)
    private String missingElements;

    @Column(nullable = false, length = 1024)
    private String summary;

    /**
     * Whether the most recent reconciliation still reproduced a low score for this slot. Reconciled
     * exactly like {@link QuantumVulnerabilityFinding}: never deleted, revived if a low score returns.
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
