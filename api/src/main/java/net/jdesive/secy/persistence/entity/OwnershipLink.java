package net.jdesive.secy.persistence.entity;

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
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * An ownership link from a target (a {@link Product} today, an {@link Asset} from M3 on) to an
 * owner — a registered {@link User}, or a free-text {@code principal} (a GitHub login, an email, a
 * team name) that an inference source emits (ROADMAP.md, M1b — "Ownership model").
 *
 * <p>The contract every future inference writer (M2's {@code GitHubSyncService}, M3's
 * {@code AwsSyncService}/{@code AzureSyncService}) must hold to:
 * <ol>
 *     <li>Exactly one of {@link #product}/{@link #asset} is set — never both, never neither
 *     (enforced by migration {@code 020}'s {@code ck_ownership_link_one_target}).</li>
 *     <li>Owner shape: {@code USER} carries a {@link #user} and/or a {@link #principal} (a
 *     registered account, an unregistered individual identified by principal, or both); {@code TEAM}
 *     carries only a {@link #principal}, never a {@link #user} (enforced by
 *     {@code ck_ownership_link_owner_shape}). A {@code MANUAL} {@code USER} link must reference a
 *     registered {@link #user} — never principal-only (enforced by
 *     {@code ck_ownership_link_manual_user_registered} and by {@code OwnershipService}).</li>
 *     <li><b>{@code MANUAL} rows are never modified or deleted by inference.</b> An M2/M3 refresh
 *     replaces only its own {@code INFERRED} rows for a given target (matched by
 *     {@code (target, ownerType, owner, source, inferenceMethod)}), never the {@code MANUAL} ones —
 *     manual intent survives an inference refresh.</li>
 *     <li>Nothing links to a tenant's Unassigned bucket ({@link Product#isUnassigned()}) — see
 *     {@code OwnershipService#assignManualProductOwner}.</li>
 *     <li>The Postgres-only unique indexes ({@code uq_ownership_link_product_owner} /
 *     {@code uq_ownership_link_asset_owner}) and CHECK constraints from migration {@code 020} have no
 *     H2 equivalent (tests build their schema from these entities via {@code ddl-auto=create-drop},
 *     not Liquibase) — {@code OwnershipService} must enforce the same rules in the service layer.</li>
 * </ol>
 */
@Getter
@Setter
@Entity
@Table(name = "ownership_link")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class OwnershipLink extends TenantOwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The owned product. Nullable — exactly one of this/{@link #asset} is set. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ToString.Exclude
    private Product product;

    /** The owned asset (M3 writer only — nothing sets this in M1b). Nullable — see {@link #product}. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ToString.Exclude
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(name = "owner_type", nullable = false, length = 16)
    private OwnerType ownerType;

    /** The registered account, when the owner is (or also is) a known user. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ToString.Exclude
    private User user;

    /** Free text: a GitHub login/email for an unregistered {@code USER}, or a team name for {@code TEAM}. */
    @Column(length = 255)
    private String principal;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private OwnershipSource source;

    @Enumerated(EnumType.STRING)
    @Column(name = "inference_method", length = 32)
    private OwnershipInferenceMethod inferenceMethod;

    /** Free text about an {@code INFERRED} link — e.g. a CODEOWNERS file:line or a team slug. */
    @Column(length = 1024)
    private String evidence;

    /**
     * Who made a {@code MANUAL} link. Nullable, {@code set null} on delete — a stand-in until the
     * Tenancy-hardening audit log exists.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_by_id")
    @OnDelete(action = OnDeleteAction.SET_NULL)
    @ToString.Exclude
    private User assignedBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
