package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

/**
 * {@code exported = false}: spring-boot-starter-data-rest is on the classpath and would otherwise
 * publish full CRUD (including PUT/PATCH/DELETE) for this repository, bypassing every guard
 * {@code ProductService} enforces — the Unassigned bucket's undeletability, its reserved name, and
 * its {@code unassigned}/{@code tagValue} invariants. {@code ProductController} already covers every
 * operation the UI actually uses.
 */
@Repository
@RepositoryRestResource(exported = false)
public interface ProductRepository extends JpaRepository<Product, UUID> {

    /**
     * {@code products.name} is unique per tenant ({@code uq_products_tenant_name}, migration 018),
     * not globally — this is unambiguous while only the default tenant exists, but M1 must switch
     * callers to a tenant-qualified lookup once a second tenant can exist. Backs the find-or-create
     * key a connector sync uses to land repeated syncs of the same {@code owner/repo} on the same
     * product — see {@code GitHubSyncService}.
     */
    Optional<Product> findByName(String name);

    /** The tenant's Unassigned bucket, if it has been created yet — see {@code ProductService#getOrCreateUnassigned}. */
    Optional<Product> findByTenantIdAndUnassignedTrue(UUID tenantId);

    /** A product answering to a given tag value within a tenant — see {@code ProductTaggingService}. */
    Optional<Product> findByTenantIdAndTagValue(UUID tenantId, String tagValue);

    /** Tenant-qualified equivalent of {@link #findByName}, for M1a's tag-value adoption path. */
    Optional<Product> findByTenantIdAndName(UUID tenantId, String name);

}
