package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SourceConnector;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SourceConnectorRepository extends JpaRepository<SourceConnector, UUID> {

    Page<SourceConnector> findAllByOrderByCreatedAtDesc(Pageable pageable);

    /** The connector a {@code CONNECTOR_SYNC} job is for. Mirrors {@code AssetRepository#findByJobId}. */
    Optional<SourceConnector> findByJobId(UUID jobId);

}
