package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface SbomQualityFindingRepository
        extends JpaRepository<SbomQualityFinding, UUID>, JpaSpecificationExecutor<SbomQualityFinding> {

    /** Prior findings for a normal (non-bucket) product — {@code SbomQualityFindingService}'s reconciliation read. */
    List<SbomQualityFinding> findAllByProductIdAndScopeSbomIdIsNull(UUID productId);

    /** Prior findings for one bucket (Unassigned) SBOM — bucket SBOMs are reconciled per-SBOM, not per-product. */
    List<SbomQualityFinding> findAllByScopeSbomId(UUID scopeSbomId);

    /** M1k — {@code LeadershipMetricsService}'s {@code weeklyFlow}: every creation timestamp since a cutoff, regardless of current state. */
    @Query("select f.createdAt from SbomQualityFinding f where f.createdAt >= :since")
    List<LocalDateTime> findCreatedAtSince(@Param("since") LocalDateTime since);

}
