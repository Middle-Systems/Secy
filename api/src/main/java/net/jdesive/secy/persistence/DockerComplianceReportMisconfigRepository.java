package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.DockerComplianceReportMisconfig;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface DockerComplianceReportMisconfigRepository
        extends JpaRepository<DockerComplianceReportMisconfig, String> {

    /**
     * A report's checks, paged, optionally narrowed to one verdict.
     *
     * <p>Ordered failures first: the list exists to be worked through, and a page of {@code PASS}
     * rows ahead of the failures would bury the work. Within a status, benchmark order.
     */
    @Query("SELECT m FROM DockerComplianceReportMisconfig m LEFT JOIN m.control c "
            + "WHERE m.report.id = :reportId AND (:status IS NULL OR m.status = :status) "
            + "ORDER BY CASE m.status WHEN net.jdesive.secy.persistence.entity.ComplianceStatus.FAIL THEN 0 "
            + "WHEN net.jdesive.secy.persistence.entity.ComplianceStatus.SKIP THEN 1 ELSE 2 END ASC, "
            + "c.controlId ASC, m.checkId ASC")
    Page<DockerComplianceReportMisconfig> findForReport(@Param("reportId") String reportId,
                                                        @Param("status") ComplianceStatus status,
                                                        Pageable pageable);

}
