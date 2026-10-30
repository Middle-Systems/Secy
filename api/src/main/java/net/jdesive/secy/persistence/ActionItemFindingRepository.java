package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.ActionItemFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** {@code exported = false} — see {@link ActionItemRepository}'s Javadoc for why. */
@Repository
@RepositoryRestResource(exported = false)
public interface ActionItemFindingRepository
        extends JpaRepository<ActionItemFinding, UUID>, JpaSpecificationExecutor<ActionItemFinding> {

    List<ActionItemFinding> findAllByActionItemId(UUID actionItemId);

    List<ActionItemFinding> findAllByActionItemIdIn(List<UUID> actionItemIds);

    Optional<ActionItemFinding> findByVulnerabilityAlertId(UUID vulnerabilityAlertId);

    Optional<ActionItemFinding> findByCompromiseFindingId(UUID compromiseFindingId);

    Optional<ActionItemFinding> findByLifecycleDriftFindingId(UUID lifecycleDriftFindingId);

    Optional<ActionItemFinding> findByQuantumVulnerabilityFindingId(UUID quantumVulnerabilityFindingId);

    Optional<ActionItemFinding> findBySbomQualityFindingId(UUID sbomQualityFindingId);

    List<ActionItemFinding> findAllByVulnerabilityAlertIdIn(List<UUID> ids);

    List<ActionItemFinding> findAllByCompromiseFindingIdIn(List<UUID> ids);

    List<ActionItemFinding> findAllByLifecycleDriftFindingIdIn(List<UUID> ids);

    List<ActionItemFinding> findAllByQuantumVulnerabilityFindingIdIn(List<UUID> ids);

    List<ActionItemFinding> findAllBySbomQualityFindingIdIn(List<UUID> ids);

}
