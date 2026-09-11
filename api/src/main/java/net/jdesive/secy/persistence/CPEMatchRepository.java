package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.CPEMatch;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CPEMatchRepository extends CrudRepository<CPEMatch, String> {

    /**
     * Candidate rows for the CPE fallback path.
     *
     * <p>This replaced an unfiltered {@code criteria LIKE :pattern} query. Two differences, both
     * load-bearing:
     *
     * <ul>
     *   <li><b>{@code vulnerable = true} only.</b> A {@code cpeMatch} row with
     *       {@code vulnerable: false} is the <em>running-on</em> half of an AND configuration —
     *       "Struts is vulnerable <i>when running on</i> Windows". Treating those as affected
     *       products is a pure false positive, and the old query returned them.</li>
     *   <li><b>Case-insensitive.</b> CPE names are case-insensitive by specification; NVD emits them
     *       lowercase but a hand-written row in a fixture or a VEX document need not be.</li>
     * </ul>
     *
     * <p>The AND/OR nesting of {@code cpe_operator} is otherwise <b>not</b> evaluated — a match on
     * any vulnerable row raises the alert. That over-reports for the handful of CVEs whose
     * configuration requires two products together, and is a deliberate Phase 2 simplification; the
     * alert's {@code matchConfidence} is what carries the caveat to the operator.
     *
     * @param pattern lowercase {@code LIKE} pattern from {@code PurlCpeBridge.CpeCandidate}
     */
    @Query("SELECT c FROM CPEMatch c "
            + "JOIN FETCH c.operator op "   // Force-load the operator
            + "JOIN FETCH op.cve "          // Force-load the actual CVE details
            + "WHERE c.vulnerable = true AND LOWER(c.criteria) LIKE :pattern")
    List<CPEMatch> findVulnerableByCriteriaLike(@Param("pattern") String pattern);

}
