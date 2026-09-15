package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SBOMComponent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Introduced in Phase 6 for one query — see {@link #findHashesByComponentIds}.
 *
 * <p>{@code sbom_component} had never needed a repository of its own: it is written through
 * {@code SBOM}'s cascade and read through the alert relations. Compromise detection is the first
 * thing that needs to read a component collection <em>without</em> a live entity graph to reach it
 * through.
 */
@Repository
public interface SBOMComponentRepository extends JpaRepository<SBOMComponent, UUID> {

    /**
     * The declared digests for a set of components, as {@code (componentId, algorithm, value)} rows.
     *
     * <p><b>Why a projection query and not {@code component.getHashes()}.</b> The SBOM handed to
     * correlation is detached — {@code VulnerabilityScanner} self-invokes its own
     * {@code @Transactional} method, so the fetch happens outside a transaction and every lazy
     * collection on the graph is bound to a session that is already closed. Reading the rows here,
     * inside detection's own transaction, makes detection independent of whatever state its caller's
     * entity graph is in. See {@code CorrelatableComponent} for the longer version.
     *
     * <p>One query for the whole scope rather than one per component: an SBOM that declares hashes
     * declares one per component, and the per-component form would be an N+1 on every upload.
     * Returns nothing at all for the common case of an SBOM with no {@code hashes[]}.
     */
    @Query("SELECT c.id, h.algorithm, h.value FROM SBOMComponent c JOIN c.hashes h WHERE c.id IN :ids")
    List<Object[]> findHashesByComponentIds(@Param("ids") Collection<UUID> ids);

}
