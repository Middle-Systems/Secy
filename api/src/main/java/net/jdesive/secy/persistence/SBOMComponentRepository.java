package net.jdesive.secy.persistence;

import net.jdesive.secy.model.lifecycle.StageComponent;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
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

    /**
     * M1c's cross-instance hash-collision pass ({@code ComponentIdentityService#flagHashIdentityCollisions}):
     * every other component in the tenant that declares one of the given digest values, as
     * {@code (componentId, identityKey, algorithm, value)} rows. Tenant-wide, not product-scoped —
     * see the roadmap's "Tenant-wide scope for digest collisions" decision.
     */
    @Query("SELECT c.id, c.identityKey, h.algorithm, h.value FROM SBOMComponent c JOIN c.hashes h JOIN c.sbom s " +
            "WHERE s.tenantId = :tenantId AND h.value IN :values AND c.identityKey IS NOT NULL")
    List<Object[]> findHashHoldersInTenant(@Param("tenantId") UUID tenantId, @Param("values") Collection<String> values);

    /**
     * Bulk-flip {@link IdentityConfidence} on components outside the current persistence context —
     * used only by the hash-collision pass to mark the <em>other</em> side of a collision when it
     * lives in a different SBOM than the one currently being ingested. Deliberately bypasses
     * {@code @PreUpdate}: those rows are not loaded into this session, so there is nothing for a
     * lifecycle callback to run against anyway.
     */
    @Modifying
    @Query("UPDATE SBOMComponent c SET c.identityConfidence = :confidence WHERE c.id IN :ids")
    int markIdentityConfidence(@Param("ids") Collection<UUID> ids, @Param("confidence") IdentityConfidence confidence);

    /** For {@code GET /sbom/{sbomId}/components/{componentId}/identity} — scoped to the named SBOM so a component id from a different SBOM 404s rather than leaking cross-document. */
    @Query("SELECT c FROM SBOMComponent c JOIN FETCH c.sbom s WHERE c.id = :componentId AND s.id = :sbomId")
    Optional<SBOMComponent> findByIdAndSbomId(@Param("componentId") UUID componentId, @Param("sbomId") UUID sbomId);

    /**
     * One SBOM's components, projected for {@code LifecycleDiffer} (M1e). The root/metadata component
     * (held on {@code sbom.component} — see {@code SBOMService#toEntity}, which also puts it in
     * {@code sbom.components} because it shares the same {@code sbom_id} FK) is deliberately excluded:
     * roots differ across stages (a repo name vs an image name) and diffing them would manufacture
     * false drift on every single pair. {@code left join s.component root} exactly mirrors
     * {@code LineageSourceReader}'s exclusion — an implicit {@code s.component.id} comparison would
     * become an inner join and silently drop every row whenever an SBOM has no root at all.
     */
    @Query("""
            select new net.jdesive.secy.model.lifecycle.StageComponent(c.id, c.identityKey, c.name, c.version, c.purl)
            from SBOM s join s.components c left join s.component root
            where s.id = :sbomId and c.identityKey is not null and (root.id is null or c.id <> root.id)
            """)
    List<StageComponent> findStageComponents(@Param("sbomId") UUID sbomId);

}
