package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.ProductTagConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Backs {@link net.jdesive.secy.service.ProductTaggingService}. {@code exported = false}: this is
 * per-tenant configuration, reachable only through {@code /settings/product-tagging}, never raw CRUD.
 */
@Repository
@RepositoryRestResource(exported = false)
public interface ProductTagConfigRepository extends JpaRepository<ProductTagConfig, UUID> {

    Optional<ProductTagConfig> findByTenantId(UUID tenantId);
}
