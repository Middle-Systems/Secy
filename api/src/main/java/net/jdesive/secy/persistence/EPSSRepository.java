package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.EPSS;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface EPSSRepository extends JpaRepository<EPSS, String> {

    @Query("SELECT e FROM EPSS e WHERE LOWER(e.cve) LIKE LOWER(CONCAT('%', :term, '%'))")
    Page<EPSS> searchEpss(@Param("term") String term, Pageable pageable);

    long countByDateAfter(LocalDateTime date);

    // For "High Probability EPSS (7d)": Score > 0.36 AND updated in last 7 days
    @Query("SELECT COUNT(e) FROM EPSS e WHERE e.epss > :score AND e.date > :date")
    long countHighProbabilityRecent(@Param("score") double score, @Param("date") LocalDateTime date);

}
