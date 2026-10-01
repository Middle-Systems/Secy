package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One user's membership in one tenant — the many-to-many join between {@link User} and
 * {@link Tenant}, modelled as an explicit entity rather than a bare {@code @ManyToMany} so a later
 * milestone can hang per-tenant roles or an invitation state off this row without a schema change.
 *
 * <p>{@code M0} writes exactly one of these per registered user, to {@link Tenant#DEFAULT_TENANT_ID}
 * — see {@code AuthService.register}. {@code M1k} (ROADMAP.md's "Role-based views") is the first to
 * actually read/write this row's access fields: it now carries whether this member is a tenant
 * admin ({@link #tenantAdmin}) and whether {@code TenantMembershipRole} rows for it are
 * authoritative ({@link #rolesConfigured} — see {@code TenantAccessService.DEFAULT_ROLES} for the
 * unconfigured default). <b>Nothing here is enforced.</b> These are schema and view-selection only;
 * a user can still call any endpoint their JWT authenticates them for regardless of role — see
 * {@code TenantAccessController}'s class Javadoc and the one deliberate exception (role-assignment
 * itself is gated to tenant admins). Real access control is the later "Tenancy hardening" milestone's
 * job.
 *
 * <p>{@link #user}'s {@code on delete cascade} is required, not decorative: {@code AuthIntegrationTest}
 * and {@code TriageServiceTest} both call {@code users.deleteAll()} between tests against the shared
 * H2 database, and once registration starts writing memberships, an unqualified user delete would
 * otherwise be blocked by this table's FK.
 *
 * <h2>Why roles are a satellite entity, not an {@code @ElementCollection}</h2>
 *
 * <p>M1k's plan called for {@code @ElementCollection Set<TenantRole> roles} directly on this entity
 * with {@code @OnDelete(CASCADE)} on its collection table — the same shape as
 * {@code SourceConnector.repoAllowlist}, minus that field's lack of any cascade need. In practice,
 * Hibernate 6.5.3's {@code CollectionBinder} rejects {@code @OnDelete} on an {@code @ElementCollection}
 * mapped via {@code @CollectionTable} outright (it demands a direct {@code @JoinColumn} on the
 * field, then rejects that very annotation as incompatible with {@code @ElementCollection} — a
 * dead end either way). {@code TenantMembershipRole} is the plan's own pre-decided fallback: a plain
 * entity holding {@code membershipId} as an un-related {@code UUID} column (the M1c/M1e/M1j
 * precedent {@link net.jdesive.secy.persistence.entity.ActionItemEvent#getFindingId()} and friends
 * use for exactly this reason) rather than a {@code @ManyToOne} back to this class. With no JPA
 * relation, Hibernate generates no H2 foreign key at all between the two tables, so deleting a
 * membership (or, transitively, a user) is never blocked by a role row — see
 * {@code TenantMembershipRoleCascadeTest} (M1k's T1), which proves exactly this. PostgreSQL still
 * gets a real {@code on delete cascade} foreign key, written directly in migration {@code 029b}.
 */
@Getter
@Setter
@Entity
@Table(name = "tenant_membership",
        uniqueConstraints = @UniqueConstraint(name = "uq_tenant_membership_tenant_user",
                columnNames = {"tenant_id", "user_id"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class TenantMembership {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    @ToString.Exclude
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ToString.Exclude
    private User user;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /**
     * Stored tenant-admin flag — M1k. The <b>effective</b> value is
     * {@code tenantAdmin || user.role == Role.ADMIN} (see {@code TenantAccessService.accessFor}),
     * so a global {@code ADMIN} is always effectively a tenant admin of every tenant even when this
     * column reads false; nobody can lock everyone out by flipping it.
     */
    @Column(name = "tenant_admin", nullable = false)
    private boolean tenantAdmin;

    /**
     * False until a tenant admin explicitly sets this membership's {@code TenantMembershipRole}
     * rows via {@code PATCH /tenant/members/{userId}} — see {@code TenantAccessService.DEFAULT_ROLES}
     * for what an unconfigured membership resolves to. True means those rows are authoritative
     * exactly as stored, including none at all (explicitly "no views").
     */
    @Column(name = "roles_configured", nullable = false)
    private boolean rolesConfigured;

    /** When {@link #tenantAdmin}/roles last changed via {@code PATCH /tenant/members/{userId}}. */
    @Column(name = "access_updated_at")
    private LocalDateTime accessUpdatedAt;

    /** Plain UUID, no {@code @ManyToOne} — M1c/M1e/M1j precedent. Who made the last access change. */
    @Column(name = "access_updated_by_id")
    private UUID accessUpdatedById;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
