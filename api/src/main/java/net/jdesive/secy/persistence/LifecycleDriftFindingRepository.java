package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface LifecycleDriftFindingRepository
        extends JpaRepository<LifecycleDriftFinding, UUID>, JpaSpecificationExecutor<LifecycleDriftFinding> {

    /**
     * The reconciliation read for {@code LifecycleDiffService.runForSbom}: every existing finding for
     * one product's one stage pair, whatever its {@code lifecycleState} — the diff service itself
     * decides what to revive, keep {@code ACTIVE}, or auto-resolve.
     */
    List<LifecycleDriftFinding> findAllByProductIdAndStagePair(UUID productId, LifecycleStagePair stagePair);

}
