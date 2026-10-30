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
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One detected disagreement between a component's declared secondary identifiers (CPE, SWID,
 * content hash) and its PURL-primary identity, or between two components' content digests (M1c,
 * ROADMAP.md — "Canonical component identity"). See {@code ComponentIdentityAssessor} (Pass A,
 * within one component) and {@code ComponentIdentityService} (Pass B, cross-instance hash
 * collisions).
 *
 * <p><b>{@link #otherComponentId} / {@link #otherIdentityKey} is a both-or-neither pair</b> — a
 * Postgres {@code check} constraint (migration {@code 021b}) enforces it at the database, and this
 * class must uphold the same rule in Java: either both are set (a {@link IdentityConflictType#HASH_IDENTITY_COLLISION}
 * naming the other side) or both are null (every within-instance conflict from Pass A). Deliberately
 * no FK on {@code otherComponentId} — it may point into a later-deletable SBOM belonging to a
 * different component graph than this row's own; a dangling id is harmless, and
 * {@link #otherIdentityKey} is the durable fact that survives the other row's deletion.
 */
@Getter
@Setter
@Entity
@Table(name = "sbom_component_identity_conflict")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SBOMComponentIdentityConflict {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "component_id")
    @JsonIgnore
    @ToString.Exclude
    private SBOMComponent component;

    @Enumerated(EnumType.STRING)
    @Column(name = "conflict_type", nullable = false, length = 32)
    private IdentityConflictType conflictType;

    @Enumerated(EnumType.STRING)
    @Column(name = "identifier_type", nullable = false, length = 16)
    private SecondaryIdentifierType identifierType;

    @Column(name = "identifier_value", nullable = false, length = 1024)
    private String identifierValue;

    /** Plain id, not an association — the other side of a {@code HASH_IDENTITY_COLLISION}, possibly in a different SBOM. */
    @Column(name = "other_component_id")
    private UUID otherComponentId;

    @Column(name = "other_identity_key", length = 512)
    private String otherIdentityKey;

    @Column(length = 1024)
    private String detail;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;

    @PrePersist
    void onCreate() {
        if (detectedAt == null) {
            detectedAt = LocalDateTime.now();
        }
    }

}
