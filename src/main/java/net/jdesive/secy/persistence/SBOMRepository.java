package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SBOM;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SBOMRepository extends CrudRepository<SBOM, String> {
}
