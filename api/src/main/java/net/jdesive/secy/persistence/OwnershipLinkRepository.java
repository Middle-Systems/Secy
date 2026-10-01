package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.OwnerType;
import net.jdesive.secy.persistence.entity.OwnershipLink;
import net.jdesive.secy.persistence.entity.OwnershipSource;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * {@code exported = false} — same reasoning as {@code ProductRepository}/{@code TenantRepository}:
 * {@code ProductOwnershipController} already covers every operation the API exposes, and Spring
 * Data REST's default CRUD would bypass {@code OwnershipService}'s guards.
 */
@RepositoryRestResource(exported = false)
public interface OwnershipLinkRepository extends JpaRepository<OwnershipLink, UUID> {

    @EntityGraph(attributePaths = {"user", "assignedBy"})
    List<OwnershipLink> findByProductIdOrderByCreatedAtAsc(UUID productId);

    Optional<OwnershipLink> findByIdAndProductId(UUID id, UUID productId);

    boolean existsByProductIdAndOwnerTypeAndUserIdAndSource(
            UUID productId, OwnerType ownerType, UUID userId, OwnershipSource source);

    boolean existsByProductIdAndOwnerTypeAndPrincipalIgnoreCaseAndSource(
            UUID productId, OwnerType ownerType, String principal, OwnershipSource source);

    /**
     * The products a user manually or automatically owns within a tenant — M1k's seam for the
     * software-engineer "my products" filter. First called by
     * {@code net.jdesive.secy.service.access.OwnedByResolver} (M1k).
     */
    @Query("select distinct l.product.id from OwnershipLink l "
            + "where l.tenantId = :tenantId and l.user.id = :userId and l.product is not null")
    List<UUID> findOwnedProductIds(@Param("tenantId") UUID tenantId, @Param("userId") UUID userId);
}
