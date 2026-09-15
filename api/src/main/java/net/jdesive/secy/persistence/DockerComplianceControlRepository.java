package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.DockerComplianceControl;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DockerComplianceControlRepository extends JpaRepository<DockerComplianceControl, String> {

    /**
     * A report's controls in benchmark order.
     *
     * <p>Ordered by the control id as a string, which for CIS numbering ({@code 1.1}, {@code 1.10},
     * {@code 1.2}) is lexical rather than numeric. Left that way on purpose: the alternative is
     * parsing dotted version numbers out of a free-text field that other benchmarks spell
     * differently, and the Compliance view groups by status before it reads the number.
     */
    List<DockerComplianceControl> findAllByReportIdOrderByControlIdAsc(String reportId);

}
