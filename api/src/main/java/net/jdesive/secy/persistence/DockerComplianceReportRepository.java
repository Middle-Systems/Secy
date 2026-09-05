package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DockerComplianceReportRepository extends CrudRepository<DockerComplianceReport, String> {
}
