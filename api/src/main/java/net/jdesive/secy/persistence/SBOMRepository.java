package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SBOMRepository extends JpaRepository<SBOM, UUID> {

    /**
     * Every currently-active SBOM for a product — safe for the Unassigned bucket (M1a), which holds
     * many unrelated SBOMs all active at once, and safe for a normal, staged product too (M1e), which
     * holds at most one active SBOM per {@link SbomLifecycleStage} slot. See
     * {@code SBOMService#createPlaceholder} for the slot rule this supports.
     *
     * <p>Replaces the old {@code findByProductIdAndActiveTrue}, which returned a single
     * {@code Optional} and threw {@code IncorrectResultSizeDataAccessException} the moment more than
     * one SBOM was active for a product — exactly what M1e's per-stage slots require.
     */
    List<SBOM> findAllByProductIdAndActiveTrue(UUID productId);

    /**
     * The current active SBOM for one stage slot of a product — the {@code LifecycleDiffService}'s
     * counterpart lookup. {@code findFirst...OrderByUploadDateDesc} rather than a plain unique lookup
     * on purpose: there is no DB constraint enforcing at most one active row per (product, stage) —
     * see {@code SBOMService}'s Javadoc — so a race between two concurrent same-stage uploads leaves a
     * newest-wins read here instead of an exception.
     */
    Optional<SBOM> findFirstByProductIdAndLifecycleStageAndActiveTrueOrderByUploadDateDesc(
            UUID productId, SbomLifecycleStage stage);

    /**
     * Every other currently-active <b>staged</b> SBOM of a product, excluding {@code excludeId} and
     * the given stage's own slot — the sibling stages that make up a staged SBOM's "product truth"
     * for {@code SbomCorrelationScope}. Stage-less (legacy whole-product) SBOMs are deliberately
     * excluded: a staged upload has already superseded any of those (see
     * {@code SBOMService#createPlaceholder}), so none should ever coexist with a staged slot in
     * practice, and this query would not union them in even if one did.
     */
    @Query("select s from SBOM s where s.product.id = :productId and s.active = true "
            + "and s.lifecycleStage is not null and s.lifecycleStage <> :stage and s.id <> :excludeId")
    List<SBOM> findActiveStagedSiblings(@Param("productId") UUID productId,
                                        @Param("stage") SbomLifecycleStage stage,
                                        @Param("excludeId") UUID excludeId);

    // Alternative if you prefer passing the Object
    List<SBOM> findByProductAndActiveTrue(Product product);

    // Useful for the UI to show history
    List<SBOM> findByProductIdOrderByUploadDateDesc(UUID productId);

    /**
     * {@code product} is joined too (M1a): {@link net.jdesive.secy.correlation.CorrelationService}
     * and {@code CompromiseDetectionService} both need {@code sbom.getProduct().isUnassigned()} to
     * decide correlation scope, and {@code VulnerabilityScanner}'s async scan calls this from a
     * worker thread whose session does not otherwise stay open long enough to lazily initialize a
     * {@code product} proxy on demand.
     */
    @Query("SELECT s FROM SBOM s LEFT JOIN FETCH s.components LEFT JOIN FETCH s.product WHERE s.id = :id")
    Optional<SBOM> findByIdWithComponents(@Param("id") UUID id);

    /** The placeholder row a {@code SBOM_UPLOAD} job was enqueued for — see {@code SBOM.jobId}. */
    Optional<SBOM> findByJobId(UUID jobId);

    /**
     * M1k — {@code LeadershipMetricsService.sbomStageCoverage}'s raw rows: every active SBOM's
     * product and stage (null = legacy/unstaged), excluding the Unassigned bucket (its SBOMs aren't
     * a product lifecycle).
     */
    @Query("select s.product.id, s.lifecycleStage from SBOM s where s.active = true and s.product.unassigned = false")
    List<Object[]> findActiveStageRowsForNonBucketProducts();

}
