package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
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
     * Used to find the current "truth" for a product to deactivate it on a new upload.
     *
     * <p><b>Never call this for the Unassigned bucket product (M1a).</b> The bucket deliberately
     * holds many unrelated SBOMs, all active at once — see {@code SBOMService#createPlaceholder},
     * which skips the deactivate-old-SBOMs step for it — so this query would throw
     * {@code IncorrectResultSizeDataAccessException} the moment a second SBOM ever landed there.
     */
    Optional<SBOM> findByProductIdAndActiveTrue(UUID productId);

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

}
