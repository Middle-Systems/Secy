package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import net.jdesive.secy.model.finding.FindingRef;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * The satellite join between one {@link ActionItem} and one row of the {@code Finding} union — the
 * generalization of {@code TriageEvent}'s two-nullable-FK XOR pattern to five typed columns (M1j).
 * Exactly one of the five id columns is set, matching {@link #findingType}; enforced here by
 * {@link #setFinding} and in Postgres by {@code ck_action_item_finding_one_target}/
 * {@code ck_action_item_finding_type_matches} (migration {@code 028b}). One finding belongs to at
 * most one action item — the five {@code uq_action_item_finding_*} unique constraints.
 *
 * <p>Plain UUID columns, not {@code @ManyToOne} — see {@link ActionItem}'s class Javadoc for why.
 */
@Getter
@Setter
@Entity
@Table(name = "action_item_finding",
        indexes = {
                @Index(name = "idx_action_item_finding_item", columnList = "action_item_id"),
                @Index(name = "idx_action_item_finding_tenant", columnList = "tenant_id")
        })
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class ActionItemFinding extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "action_item_id", nullable = false)
    private UUID actionItemId;

    @Enumerated(EnumType.STRING)
    @Column(name = "finding_type", nullable = false, length = 32)
    private FindingType findingType;

    @Column(name = "vulnerability_alert_id")
    private UUID vulnerabilityAlertId;

    @Column(name = "compromise_finding_id")
    private UUID compromiseFindingId;

    @Column(name = "lifecycle_drift_finding_id")
    private UUID lifecycleDriftFindingId;

    @Column(name = "quantum_vulnerability_finding_id")
    private UUID quantumVulnerabilityFindingId;

    @Column(name = "sbom_quality_finding_id")
    private UUID sbomQualityFindingId;

    @Column(name = "attached_by_id", nullable = false)
    private UUID attachedById;

    @Column(name = "attached_at", nullable = false)
    private LocalDateTime attachedAt;

    /** Sets {@link #findingType} and the matching id column, nulling the other four. */
    public void setFinding(FindingType type, UUID id) {
        if (type == null || !type.backedByTable()) {
            throw new IllegalArgumentException("no finding table backs " + type);
        }
        this.findingType = type;
        this.vulnerabilityAlertId = null;
        this.compromiseFindingId = null;
        this.lifecycleDriftFindingId = null;
        this.quantumVulnerabilityFindingId = null;
        this.sbomQualityFindingId = null;
        switch (type) {
            case VULNERABILITY -> this.vulnerabilityAlertId = id;
            case COMPROMISE -> this.compromiseFindingId = id;
            case LIFECYCLE_DRIFT -> this.lifecycleDriftFindingId = id;
            case QUANTUM_VULNERABLE -> this.quantumVulnerabilityFindingId = id;
            case SBOM_QUALITY -> this.sbomQualityFindingId = id;
            case PROVENANCE -> throw new IllegalArgumentException("no finding table backs PROVENANCE");
        }
    }

    /** Whichever of the five id columns {@link #findingType} points at. */
    @JsonIgnore
    public UUID getFindingId() {
        if (findingType == null) {
            return null;
        }
        return switch (findingType) {
            case VULNERABILITY -> vulnerabilityAlertId;
            case COMPROMISE -> compromiseFindingId;
            case LIFECYCLE_DRIFT -> lifecycleDriftFindingId;
            case QUANTUM_VULNERABLE -> quantumVulnerabilityFindingId;
            case SBOM_QUALITY -> sbomQualityFindingId;
            case PROVENANCE -> null;
        };
    }

    /** {@link #findingType} + {@link #getFindingId()} as one value. */
    @JsonIgnore
    public FindingRef ref() {
        return new FindingRef(findingType, getFindingId());
    }

    @PrePersist
    void onCreate() {
        if (this.attachedAt == null) {
            this.attachedAt = LocalDateTime.now();
        }
    }

}
