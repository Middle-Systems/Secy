package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.ActionItemEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/** {@code exported = false} — see {@link ActionItemRepository}'s Javadoc for why. */
@Repository
@RepositoryRestResource(exported = false)
public interface ActionItemEventRepository extends JpaRepository<ActionItemEvent, UUID> {

    /** One item's history, oldest first — {@code GET /action-items/{id}/history}. */
    List<ActionItemEvent> findAllByActionItemIdOrderByCreatedAtAsc(UUID actionItemId);

}
