package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.CPEMatch;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CPEMatchRepository extends CrudRepository<CPEMatch, String> {
}
