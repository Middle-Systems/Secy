package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.AssetComponent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface AssetComponentRepository extends JpaRepository<AssetComponent, UUID> {

    /**
     * Every component row an asset has ever had, present or not.
     *
     * <p>The scan upserts against this set by {@code identityKey}: a package still reported keeps its
     * row (and therefore its alerts), one that has vanished is flipped to
     * {@code presentInLastScan = false} rather than deleted.
     */
    List<AssetComponent> findAllByAssetId(UUID assetId);

    List<AssetComponent> findAllByAssetIdAndPresentInLastScanTrue(UUID assetId);

    /**
     * The declared digests for a set of components, as {@code (componentId, algorithm, value)} rows —
     * the asset-side twin of {@code SBOMComponentRepository.findHashesByComponentIds}, with the same
     * reasoning and the same one-query-per-scope shape.
     *
     * <p>Returns nothing today for every real scan: neither {@code TrivyNormalizer} nor
     * {@code GrypeNormalizer} reads a package-level digest, so {@code asset_component_hash} is only
     * ever populated by a caller that sets it directly. The query exists so the matcher behaves
     * identically for both component kinds the moment that changes — see {@code AssetComponent.hashes}.
     */
    @Query("SELECT c.id, h.algorithm, h.value FROM AssetComponent c JOIN c.hashes h WHERE c.id IN :ids")
    List<Object[]> findHashesByComponentIds(@Param("ids") Collection<UUID> ids);

}
