package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.VexPrecedenceConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface VexPrecedenceConfigRepository extends JpaRepository<VexPrecedenceConfig, UUID> {

    Optional<VexPrecedenceConfig> findByTenantId(UUID tenantId);

}
