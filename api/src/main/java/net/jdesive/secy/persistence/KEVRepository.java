package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.KEV;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface KEVRepository extends JpaRepository<KEV, String> {

    @Query("SELECT k FROM KEV k WHERE " +
            "LOWER(k.cveId) LIKE LOWER(CONCAT('%', :term, '%')) OR " +
            "LOWER(k.vendor) LIKE LOWER(CONCAT('%', :term, '%')) OR " +
            "LOWER(k.product) LIKE LOWER(CONCAT('%', :term, '%'))")
    Page<KEV> searchKev(@Param("term") String term, Pageable pageable);

    long countByAddedAfter(LocalDateTime date);

}
