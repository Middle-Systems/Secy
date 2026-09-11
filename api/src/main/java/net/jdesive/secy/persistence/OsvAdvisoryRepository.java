package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.OsvAdvisory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The OSV mirror, read by the correlation engine and written by the OSV feed ingester.
 *
 * <p>{@link #findForPackage} is the hot query — it runs once per SBOM component — and is written to
 * return everything the matcher needs in one round trip: the advisory, its affected ranges, its
 * aliases (to resolve a CVE) and its enumerated versions. Hibernate permits at most one bag
 * (a {@code List} with no order column) per fetch join, which is why {@code aliases} and
 * {@code versions} are {@code Set}s on the entity and only {@code ranges} is a {@code List}.
 */
@Repository
public interface OsvAdvisoryRepository extends JpaRepository<OsvAdvisory, UUID> {

    /**
     * Every advisory for one package, fully loaded.
     *
     * <p>Case-insensitive on both sides: OSV writes {@code Maven} and {@code PyPI} where a PURL
     * writes {@code maven} and {@code pypi}, and npm package names are lowercase by convention but
     * not by rule.
     *
     * @param ecosystem   OSV ecosystem name, e.g. {@code npm} / {@code Maven} / {@code PyPI}
     * @param packageName ecosystem-native name, e.g. {@code org.apache.logging.log4j:log4j-core}
     */
    @Query("SELECT DISTINCT a FROM OsvAdvisory a "
            + "LEFT JOIN FETCH a.ranges "
            + "LEFT JOIN FETCH a.aliases "
            + "LEFT JOIN FETCH a.versions "
            + "WHERE LOWER(a.ecosystem) = LOWER(:ecosystem) "
            + "AND LOWER(a.packageName) = LOWER(:packageName)")
    List<OsvAdvisory> findForPackage(@Param("ecosystem") String ecosystem,
                                     @Param("packageName") String packageName);

    /**
     * The Spring-Data-derived spelling of {@link #findForPackage}, without the eager fetches.
     *
     * <p>Present because it is the name the contract promises and the shape callers reach for; use
     * {@link #findForPackage} inside the matcher, where the collections are always needed.
     */
    List<OsvAdvisory> findByEcosystemIgnoreCaseAndPackageNameIgnoreCase(String ecosystem, String packageName);

    /** Whether OSV covers this package at all — the test that decides if the CPE fallback runs. */
    boolean existsByEcosystemIgnoreCaseAndPackageNameIgnoreCase(String ecosystem, String packageName);

    /* ------------------------------------------------------------------ */
    /* Ingest-side                                                        */
    /* ------------------------------------------------------------------ */

    /** Upsert key for the feed ingester: one row per (record, ecosystem, package). */
    Optional<OsvAdvisory> findByOsvIdAndEcosystemAndPackageName(String osvId, String ecosystem, String packageName);

    /** Every row a single OSV record produced — a multi-package record fans out to several. */
    List<OsvAdvisory> findByOsvId(String osvId);

    long countByEcosystemIgnoreCase(String ecosystem);

    /**
     * The newest record {@code modified} timestamp held for an ecosystem. The ingester may use this
     * instead of {@code OsvEcosystemCursor} to recover a lost cursor.
     */
    @Query("SELECT MAX(a.modified) FROM OsvAdvisory a WHERE LOWER(a.ecosystem) = LOWER(:ecosystem)")
    java.time.LocalDateTime findLatestModified(@Param("ecosystem") String ecosystem);

    @Modifying
    @Query("DELETE FROM OsvAdvisory a WHERE LOWER(a.ecosystem) = LOWER(:ecosystem)")
    int deleteByEcosystemIgnoreCase(@Param("ecosystem") String ecosystem);

}
