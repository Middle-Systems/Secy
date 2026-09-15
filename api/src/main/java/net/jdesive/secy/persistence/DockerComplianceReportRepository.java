package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface DockerComplianceReportRepository extends JpaRepository<DockerComplianceReport, String> {

    /** Which report a {@code COMPLIANCE_SCAN} job is for. Mirrors {@code AssetRepository#findByJobId}. */
    Optional<DockerComplianceReport> findByJobId(UUID jobId);

    /**
     * {@code GET /compliance/reports}, newest first.
     *
     * <p>Newest first rather than by name, because a compliance report is a dated audit and the
     * question is always "where do we stand now" — the previous ones are the trend behind it.
     */
    @Query("SELECT r FROM DockerComplianceReport r LEFT JOIN r.asset a "
            + "WHERE (:assetId IS NULL OR a.id = :assetId) "
            + "ORDER BY r.createdAt DESC")
    Page<DockerComplianceReport> search(@Param("assetId") UUID assetId, Pageable pageable);

}
