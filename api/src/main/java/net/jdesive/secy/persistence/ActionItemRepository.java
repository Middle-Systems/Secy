package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.ActionItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * {@code exported = false} — see {@code TenantRepository}'s Javadoc for why: Spring Data REST would
 * otherwise publish raw CRUD that bypasses every rule {@code ActionItemService} enforces (scope
 * derivation, status-machine transitions, risk-acceptance validation).
 */
@Repository
@RepositoryRestResource(exported = false)
public interface ActionItemRepository extends JpaRepository<ActionItem, UUID>, JpaSpecificationExecutor<ActionItem> {

    List<ActionItem> findAllByProductId(UUID productId);

    List<ActionItem> findAllByAssetId(UUID assetId);

    List<ActionItem> findAllByAssigneeId(UUID assigneeId);

}
