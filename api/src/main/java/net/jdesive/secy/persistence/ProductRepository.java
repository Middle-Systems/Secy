package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProductRepository extends JpaRepository<Product, UUID> {

    /**
     * {@code products.name} carries a DB-level unique constraint (see the baseline schema), so this
     * is the find-or-create key a connector sync uses to land repeated syncs of the same
     * {@code owner/repo} on the same product — see {@code GitHubSyncService}.
     */
    Optional<Product> findByName(String name);

}