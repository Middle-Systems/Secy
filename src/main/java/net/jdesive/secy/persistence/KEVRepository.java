package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.KEV;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KEVRepository extends CrudRepository<KEV, String> {
}
