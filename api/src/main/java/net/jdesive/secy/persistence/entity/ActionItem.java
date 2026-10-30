package net.jdesive.secy.persistence.entity;

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
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A concrete remediation task covering one or more {@code Finding}s (M1j — ROADMAP.md's "Finding
 * &amp; Action-item model"). See {@code net.jdesive.secy.service.actionitem.ActionItemService} for
 * every rule below; this class is deliberately a plain data holder with no business logic of its
 * own, the same discipline {@link VulnerabilityAlert}/{@link CompromiseFinding} follow.
 *
 * <h2>Manual creation only</h2>
 *
 * <p>Unlike the five finding tables, which are machine-reconciled facts, nothing ever auto-creates
 * an {@code ActionItem} — grouping findings under one remediation task is a human judgment call.
 * Auto-<em>reopen</em> is still fully automatic (it is derived, not created — see
 * {@code RemediationStatusDeriver}).
 *
 * <h2>Exactly one scope</h2>
 *
 * <p>{@link #productId} XOR {@link #assetId} — enforced by {@code ck_action_item_one_scope}
 * (migration {@code 028a}) in Postgres and re-checked in {@code ActionItemService} for H2. The scope
 * is <b>derived</b> from the attached findings at creation time, never client-supplied, and every
 * finding attached later must share it. A cross-product "upgrade everywhere" campaign is therefore N
 * action items, one per product — see the class Javadoc note in {@code ActionItemService}.
 *
 * <h2>Why every reference is a plain UUID, no {@code @ManyToOne}</h2>
 *
 * <p>Same reasoning as {@link LifecycleDriftFinding}/{@link QuantumVulnerabilityFinding}/
 * {@link SbomQualityFinding} — a JPA association here, including to {@code app_user}, would create
 * an H2 foreign key that breaks {@code appUserRepository.deleteAll()} in the many non-transactional
 * test classes that call it in {@code @BeforeEach}. PostgreSQL still gets real foreign keys, on
 * delete cascade for product/asset, plain references for every {@code app_user} FK (migration
 * {@code 028a}).
 *
 * <h2>Never deleted</h2>
 *
 * <p>No {@code DELETE} endpoint exists. The terminal state is {@link RemediationStatus#RESOLVED};
 * a mistaken grouping is fixed by detaching findings, not by removing the row.
 */
@Getter
@Setter
@Entity
@Table(name = "action_item",
        indexes = {
                @Index(name = "idx_action_item_tenant", columnList = "tenant_id"),
                @Index(name = "idx_action_item_product_status", columnList = "product_id, status"),
                @Index(name = "idx_action_item_asset_status", columnList = "asset_id, status"),
                @Index(name = "idx_action_item_assignee", columnList = "assignee_id")
        })
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class ActionItem extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(length = 4096)
    private String description;

    /** Exactly one of {@link #productId}/{@link #assetId} is set — see the class Javadoc. */
    @Column(name = "product_id")
    private UUID productId;

    @Column(name = "asset_id")
    private UUID assetId;

    /**
     * The last human decision. Only {@code OPEN}/{@code IN_PROGRESS}/{@code RISK_ACCEPTED}/
     * {@code RESOLVED} are ever stored here — {@code NOT_AFFECTED} is derived-only, see
     * {@link RemediationStatus}. The item's <em>effective</em> status (what a client should show) can
     * differ from this — see {@code RemediationStatusDeriver.forItem}.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private RemediationStatus status = RemediationStatus.OPEN;

    @Column(name = "assignee_id")
    private UUID assigneeId;

    @Column(name = "created_by_id", nullable = false)
    private UUID createdById;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /** Set only while {@link #status} is {@code RESOLVED}; cleared the moment it leaves that status. */
    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    /* ------------------------------------------------------------------ */
    /* Risk acceptance (M1j §5 — schema-only, no approval enforcement)    */
    /* ------------------------------------------------------------------ */

    @Column(name = "risk_accepted_until")
    private LocalDateTime riskAcceptedUntil;

    @Column(name = "risk_accepted_at")
    private LocalDateTime riskAcceptedAt;

    @Column(name = "risk_accepted_by_id")
    private UUID riskAcceptedById;

    @Column(name = "risk_acceptance_justification", length = 4096)
    private String riskAcceptanceJustification;

    /** Optional; may equal {@link #riskAcceptedById} — no separation-of-duties check yet, see §5. */
    @Column(name = "risk_approved_by_id")
    private UUID riskApprovedById;

    @Column(name = "risk_approval_note", length = 4096)
    private String riskApprovalNote;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (this.createdAt == null) {
            this.createdAt = now;
        }
        if (this.updatedAt == null) {
            this.updatedAt = now;
        }
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
