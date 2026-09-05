package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.CPEMatch;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CPEMatchRepository extends CrudRepository<CPEMatch, String> {

    @Query("SELECT c FROM CPEMatch c " +
            "JOIN FETCH c.operator op " + // Force-load the operator
            "JOIN FETCH op.cve " +        // Force-load the actual CVE details
            "WHERE c.criteria LIKE :pattern")
    List<CPEMatch> findByCriteriaWithDetails(@Param("pattern") String pattern);

}
