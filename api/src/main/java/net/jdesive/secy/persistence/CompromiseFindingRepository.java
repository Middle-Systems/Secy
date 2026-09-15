package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface CompromiseFindingRepository
        extends JpaRepository<CompromiseFinding, UUID>, JpaSpecificationExecutor<CompromiseFinding> {

    /* ------------------------------------------------------------------ */
    /* Detection — the prior set, per scope                                */
    /* ------------------------------------------------------------------ */

    /**
     * Every finding already on record for one <b>product</b>, across all of its SBOM versions.
     *
     * <p>Product-scoped, not SBOM-scoped, for exactly the reason
     * {@code VulnerabilityAlertRepository.findAllByProductIdForCorrelation} is: every upload writes
     * fresh {@code sbom_component} rows, so an SBOM-scoped prior set is always empty on a new upload
     * and nothing ever gets auto-resolved.
     */
    @Query("SELECT f FROM CompromiseFinding f JOIN FETCH f.component c WHERE c.sbom.product.id = :productId")
    List<CompromiseFinding> findAllByProductIdForDetection(@Param("productId") UUID productId);

    /** The product-less fallback, for an SBOM that belongs to no product (only ever a test fixture). */
    @Query("SELECT f FROM CompromiseFinding f JOIN FETCH f.component c WHERE c.sbom.id = :sbomId")
    List<CompromiseFinding> findAllBySbomIdForDetection(@Param("sbomId") UUID sbomId);

    /** Every finding already on record for one <b>asset</b>. */
    @Query("SELECT f FROM CompromiseFinding f JOIN FETCH f.assetComponent c WHERE c.asset.id = :assetId")
    List<CompromiseFinding> findAllByAssetIdForDetection(@Param("assetId") UUID assetId);

    /* ------------------------------------------------------------------ */
    /* Housekeeping                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Every finding citing a component of one asset, whatever its lifecycle state.
     *
     * <p>{@code DELETE /assets/{id}} needs this: a finding holds an FK into {@code asset_component},
     * so the asset cannot be removed while one exists. Mirrors
     * {@code VulnerabilityAlertRepository.findAllByAssetId}.
     */
    @Query("SELECT f FROM CompromiseFinding f JOIN f.assetComponent c WHERE c.asset.id = :assetId")
    List<CompromiseFinding> findAllByAssetId(@Param("assetId") UUID assetId);

    /**
     * Candidates for IOC aging: still active, still claiming a live verdict.
     *
     * <p>The staleness cut-off is applied in SQL against {@code iocLastSeen} with the two fallbacks
     * {@code CompromiseFinding.freshnessReference()} describes, so the job loads only the rows it is
     * actually going to demote rather than scanning the whole table in Java.
     */
    @Query("SELECT f FROM CompromiseFinding f WHERE f.lifecycleState = :state "
            + "AND f.confidence IN :confidences "
            + "AND COALESCE(f.iocLastSeen, f.iocFirstSeen, f.createdAt) < :staleBefore")
    List<CompromiseFinding> findStale(@Param("state") AlertLifecycleState state,
                                      @Param("confidences") Collection<CompromiseConfidence> confidences,
                                      @Param("staleBefore") LocalDateTime staleBefore);

    /* ------------------------------------------------------------------ */
    /* Dashboard roll-ups                                                  */
    /* ------------------------------------------------------------------ */

    /**
     * The headline compromise tile. Scoped to {@code ACTIVE} so it matches what
     * {@code GET /actionable} and {@code GET /compromise} show, by construction — the same discipline
     * {@code countActionableByAsset} follows.
     */
    long countByLifecycleState(AlertLifecycleState lifecycleState);

    long countByLifecycleStateAndConfidence(AlertLifecycleState lifecycleState,
                                            CompromiseConfidence confidence);

    long countByLifecycleStateAndCreatedAtAfter(AlertLifecycleState lifecycleState, LocalDateTime since);

    /** Per-asset compromise counts for a page of assets, in one query rather than one per row. */
    @Query("SELECT c.asset.id, COUNT(f) FROM CompromiseFinding f JOIN f.assetComponent c "
            + "WHERE c.asset.id IN :assetIds AND f.lifecycleState = "
            + "net.jdesive.secy.persistence.entity.AlertLifecycleState.ACTIVE "
            + "GROUP BY c.asset.id")
    List<Object[]> countActiveByAsset(@Param("assetIds") List<UUID> assetIds);

}
