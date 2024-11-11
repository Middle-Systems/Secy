package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.DockerMisconfigurationAlert;
import net.jdesive.secy.persistence.entity.DockerVulnerabilityAlert;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DockerMisconfigurationAlertRepository extends CrudRepository<DockerMisconfigurationAlert, String> {
}
