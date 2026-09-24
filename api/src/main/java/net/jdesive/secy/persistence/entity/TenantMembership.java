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
 * — see {@code AuthService.register}. Nothing else reads or writes this table yet.
 *
 * <p>{@link #user}'s {@code on delete cascade} is required, not decorative: {@code AuthIntegrationTest}
 * and {@code TriageServiceTest} both call {@code users.deleteAll()} between tests against the shared
 * H2 database, and once registration starts writing memberships, an unqualified user delete would
 * otherwise be blocked by this table's FK.
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

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
