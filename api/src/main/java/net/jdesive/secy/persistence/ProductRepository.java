package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProductRepository extends JpaRepository<Product, UUID> {

    /**
     * {@code products.name} is unique per tenant ({@code uq_products_tenant_name}, migration 018),
     * not globally — this is unambiguous while only the default tenant exists, but M1 must switch
     * callers to a tenant-qualified lookup once a second tenant can exist. Backs the find-or-create
     * key a connector sync uses to land repeated syncs of the same {@code owner/repo} on the same
     * product — see {@code GitHubSyncService}.
     */
    Optional<Product> findByName(String name);

}