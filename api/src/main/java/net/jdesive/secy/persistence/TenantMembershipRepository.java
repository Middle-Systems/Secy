package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.TenantMembership;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** {@code exported = false} — see {@code TenantRepository}'s Javadoc for why. */
@RepositoryRestResource(exported = false)
public interface TenantMembershipRepository extends JpaRepository<TenantMembership, UUID> {

    List<TenantMembership> findByUserId(UUID userId);

    boolean existsByTenantIdAndUserId(UUID tenantId, UUID userId);

    /** M1k — {@code TenantAccessService}'s per-user lookup. */
    Optional<TenantMembership> findByTenantIdAndUserId(UUID tenantId, UUID userId);

    /** M1k — {@code GET /tenant/members}; eager-fetches {@code user} to avoid N+1 on the listing. */
    @EntityGraph(attributePaths = "user")
    List<TenantMembership> findAllByTenantId(UUID tenantId);
}
