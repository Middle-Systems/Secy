package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.VexStatement;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface VexStatementRepository extends JpaRepository<VexStatement, UUID>, JpaSpecificationExecutor<VexStatement> {

    /** Resolution read — caller chunks {@code cveIds} at 500. */
    List<VexStatement> findAllByTenantIdAndActiveTrueAndCveIdIn(UUID tenantId, Collection<String> cveIds);

    boolean existsByTenantIdAndActiveTrue(UUID tenantId);

    @Query("select distinct s.cveId from VexStatement s where s.tenantId = :tenantId and s.active = true")
    List<String> findDistinctActiveCveIds(@Param("tenantId") UUID tenantId);

    @Query("select distinct s.cveId from VexStatement s where s.documentId = :documentId")
    List<String> findDistinctCveIdsByDocumentId(@Param("documentId") UUID documentId);

    @Modifying
    @Query("update VexStatement s set s.active = false where s.documentId = :documentId")
    int deactivateAllByDocumentId(@Param("documentId") UUID documentId);

    Page<VexStatement> findAllByDocumentIdOrderByOrdinalAsc(UUID documentId, Pageable pageable);

}
