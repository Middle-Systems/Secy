package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.MaliciousPackage;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MaliciousPackageRepository extends JpaRepository<MaliciousPackage, UUID> {

    /**
     * Every malicious-package record naming this package, with its version list and ranges loaded.
     *
     * <p>The detection hot path. Case-insensitive on both halves for the same reason
     * {@code OsvAdvisoryRepository.findForPackage} is: the upstream repository's directory names are
     * lower-cased ({@code osv/malicious/pypi/…}) while the records inside spell the ecosystem
     * canonically ({@code PyPI}), and npm package names are lower-case by registry rule but SBOM
     * generators do not always honour that.
     *
     * <p>{@code LEFT JOIN FETCH} on both collections plus {@code DISTINCT}: they are
     * {@code FetchType.LAZY} and the matcher reads both for every candidate, so fetching them here
     * turns what would be two extra queries per record into none.
     */
    @Query("SELECT DISTINCT p FROM MaliciousPackage p "
            + "LEFT JOIN FETCH p.versions "
            + "LEFT JOIN FETCH p.ranges "
            + "WHERE LOWER(p.ecosystem) = LOWER(:ecosystem) AND LOWER(p.packageName) = LOWER(:packageName)")
    List<MaliciousPackage> findForPackage(@Param("ecosystem") String ecosystem,
                                          @Param("packageName") String packageName);

    /**
     * The ingester's upsert key, <b>with both child collections fetched</b>.
     *
     * <p>The fetch join is load-bearing, not an optimisation. The ingest runs from {@code JobRunner}
     * with no surrounding transaction, and its per-record upsert is a self-invocation
     * ({@code ingest} → {@code processRecord} → {@code upsert} on one bean), so Spring's proxy never
     * applies and the {@code @Transactional} on {@code upsert} is inert. On a re-ingest the upsert
     * clears and rebuilds {@code versions} and {@code ranges} — which, on a row loaded without this
     * join, means touching two {@code FetchType.LAZY} collections whose session has already closed.
     *
     * <p>{@code DISTINCT} because fetching two collections at once multiplies the rows.
     */
    @Query("SELECT DISTINCT p FROM MaliciousPackage p "
            + "LEFT JOIN FETCH p.versions "
            + "LEFT JOIN FETCH p.ranges "
            + "WHERE p.malId = :malId AND p.ecosystem = :ecosystem AND p.packageName = :packageName")
    Optional<MaliciousPackage> findForUpsert(@Param("malId") String malId,
                                             @Param("ecosystem") String ecosystem,
                                             @Param("packageName") String packageName);

    /** Plain key lookup, with no collections. Used by tests that assert on the row itself. */
    Optional<MaliciousPackage> findByMalIdAndEcosystemAndPackageName(String malId, String ecosystem,
                                                                     String packageName);

    /** Every row an upstream record wrote, for the withdrawal path. */
    List<MaliciousPackage> findByMalId(String malId);

    /** Browse the mirror — a nice-to-have for the UI, not used by detection. */
    @Query("SELECT p FROM MaliciousPackage p WHERE "
            + "(:ecosystem IS NULL OR LOWER(p.ecosystem) = LOWER(:ecosystem)) AND "
            + "(:packageName IS NULL OR LOWER(p.packageName) LIKE LOWER(CONCAT('%', :packageName, '%')))")
    Page<MaliciousPackage> search(@Param("ecosystem") String ecosystem,
                                  @Param("packageName") String packageName,
                                  Pageable pageable);

}
