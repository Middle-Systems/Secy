package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.TriageEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface TriageEventRepository extends JpaRepository<TriageEvent, UUID> {

    /** One item's history, oldest first — the chronological timeline {@code GET /actionable/{id}/history} returns. */
    List<TriageEvent> findAllByVulnerabilityAlertIdOrderByCreatedAtAsc(UUID vulnerabilityAlertId);

    /** The compromise-finding counterpart of {@link #findAllByVulnerabilityAlertIdOrderByCreatedAtAsc}. */
    List<TriageEvent> findAllByCompromiseFindingIdOrderByCreatedAtAsc(UUID compromiseFindingId);

}
