package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * One {@link TenantRole} held by one {@link TenantMembership} — M1k's satellite-entity fallback for
 * what the plan originally specified as an {@code @ElementCollection} directly on
 * {@code TenantMembership} (see that class's Javadoc for exactly why the fallback was needed).
 *
 * <p>{@link #membershipId} is a plain, un-related {@code UUID} column — no {@code @ManyToOne} back
 * to {@link TenantMembership} — matching the M1c/M1e/M1j precedent of a bare id column where a real
 * JPA relation would make Hibernate generate an H2 foreign key that could block an unrelated test's
 * {@code userRepository.deleteAll()}. PostgreSQL still gets a real {@code on delete cascade} foreign
 * key, written directly in migration {@code 029b-tenant-membership-role}.
 */
@Getter
@Setter
@Entity
@Table(name = "tenant_membership_role",
        uniqueConstraints = @UniqueConstraint(name = "uq_tenant_membership_role",
                columnNames = {"membership_id", "role"}))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class TenantMembershipRole {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "membership_id", nullable = false)
    private UUID membershipId;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 32, nullable = false)
    private TenantRole role;

}
