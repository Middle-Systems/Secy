package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AssetRepository extends JpaRepository<Asset, UUID> {

    /**
     * The upsert key for a scan: re-scanning {@code acme/api:1.4.2} must land on the same row, or the
     * alert lifecycle has nothing to reconcile against.
     */
    Optional<Asset> findByTypeAndName(AssetType type, String name);

    /** Which asset an {@code ASSET_SCAN} job is for. Mirrors {@code SBOMRepository#findByJobId}. */
    Optional<Asset> findByJobId(UUID jobId);

    /**
     * {@code GET /assets}, paged, with both filters optional.
     *
     * <p>Written as one JPQL query with null-guards rather than a {@code Specification}: there are
     * exactly two dimensions and neither needs a join predicate.
     */
    @Query("SELECT a FROM Asset a LEFT JOIN a.product p "
            + "WHERE (:type IS NULL OR a.type = :type) "
            + "AND (:productId IS NULL OR p.id = :productId) "
            + "ORDER BY a.name ASC")
    Page<Asset> search(@Param("type") AssetType type, @Param("productId") UUID productId, Pageable pageable);

    /**
     * Component counts for a page of assets, in one query rather than one per row.
     *
     * <p>Counts only components the last scan still reported — a row kept as evidence of something
     * that has since been removed from the image is not part of the asset's current inventory.
     */
    @Query("SELECT c.asset.id, COUNT(c) FROM AssetComponent c "
            + "WHERE c.asset.id IN :assetIds AND c.presentInLastScan = true "
            + "GROUP BY c.asset.id")
    List<Object[]> countComponentsByAsset(@Param("assetIds") List<UUID> assetIds);

}
