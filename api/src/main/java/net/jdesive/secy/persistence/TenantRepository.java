package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.Optional;
import java.util.UUID;

/**
 * {@code exported = false}: spring-boot-starter-data-rest is on the classpath and would otherwise
 * publish a public CRUD endpoint for this repository — any authenticated user could then list,
 * create or delete tenants. M0 has no tenant CRUD endpoint at all; see ROADMAP.md.
 */
@RepositoryRestResource(exported = false)
public interface TenantRepository extends JpaRepository<Tenant, UUID> {

    Optional<Tenant> findBySlug(String slug);
}
