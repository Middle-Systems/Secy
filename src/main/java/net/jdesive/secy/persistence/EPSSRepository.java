package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.EPSS;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EPSSRepository extends CrudRepository<EPSS, String> {
}
