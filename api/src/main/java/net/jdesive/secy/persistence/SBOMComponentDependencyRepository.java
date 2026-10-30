package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentDependency;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.UUID;

/**
 * {@code exported = false} — same reasoning as {@code OwnershipLinkRepository}/{@code
 * ActionItemRepository} (M1c/M1j/M1k precedent): no controller exposes raw CRUD over this table,
 * {@code SBOMService} and {@code LineageSourceReader} are its only readers/writers (M1l).
 */
@RepositoryRestResource(exported = false)
public interface SBOMComponentDependencyRepository extends JpaRepository<SBOMComponentDependency, UUID> {

    List<SBOMComponentDependency> findBySbomId(UUID sbomId);

    /**
     * Every {@link SBOMComponent} of {@code sbomId} whose {@code bomRef} is one of {@code refs} —
     * {@code ActionableService#toDependencyContext}'s path-hop resolution (M1l). Zero or multiple
     * matches for a given ref both read back as "unresolved" at the call site, rather than being
     * guarded against here.
     */
    @Query("select c from SBOMComponent c where c.sbom.id = :sbomId and c.bomRef in :refs")
    List<SBOMComponent> findComponentsBySbomIdAndBomRefIn(@Param("sbomId") UUID sbomId, @Param("refs") List<String> refs);

}
