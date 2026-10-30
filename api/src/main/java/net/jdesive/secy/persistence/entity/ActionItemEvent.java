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
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One append-only row of an {@link ActionItem}'s history — the M1j analogue of {@code TriageEvent},
 * broadened to cover status changes, (un)assignment, finding attach/detach and comments in one
 * timeline (see {@link ActionItemEventType}).
 *
 * <p>{@link #findingId} is deliberately a plain column with <b>no foreign key, even in Postgres</b>
 * — unlike {@link ActionItemFinding}'s five typed columns — so this row's history survives a finding
 * whose backing row (or its parent SBOM/asset) is later deleted.
 */
@Getter
@Setter
@Entity
@Table(name = "action_item_event",
        indexes = @Index(name = "idx_action_item_event_item_created", columnList = "action_item_id, created_at"))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class ActionItemEvent extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "action_item_id", nullable = false)
    private UUID actionItemId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 32)
    private ActionItemEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "from_status", length = 16)
    private RemediationStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "to_status", length = 16)
    private RemediationStatus toStatus;

    /** Set only when {@link #fromStatus} was a derived value, not the stored one — see {@link StatusDerivation}. */
    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private StatusDerivation derivation;

    @Enumerated(EnumType.STRING)
    @Column(name = "finding_type", length = 32)
    private FindingType findingType;

    /** No FK — see the class Javadoc. */
    @Column(name = "finding_id")
    private UUID findingId;

    /** The new assignee, on an {@code ASSIGNED} event. */
    @Column(name = "assignee_id")
    private UUID assigneeId;

    /** Snapshot of the acceptance's expiry at the moment the item entered/renewed {@code RISK_ACCEPTED}. */
    @Column(name = "risk_accepted_until")
    private LocalDateTime riskAcceptedUntil;

    @Column(name = "risk_approved_by_id")
    private UUID riskApprovedById;

    /**
     * The authored VEX document a {@code DISPUTED} event queued — M1k. Plain UUID, with a real FK
     * in Postgres (migration {@code 029c}) but {@code on delete set null}, matching the "history
     * outlives a deleted referent" discipline above for {@link #findingId}, one step short: this one
     * DOES get an FK since {@code vex_document} rows are never deleted, only deactivated.
     */
    @Column(name = "vex_document_id")
    private UUID vexDocumentId;

    @Column(length = 4096)
    private String comment;

    @Column(name = "changed_by_id", nullable = false)
    private UUID changedById;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
