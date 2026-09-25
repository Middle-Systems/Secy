package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexOrigin;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VexDocumentRepository extends JpaRepository<VexDocument, UUID> {

    Optional<VexDocument> findByJobId(UUID jobId);

    /**
     * Candidates for supersession — the caller filters {@code scopeProductId} in Java with
     * {@link java.util.Objects#equals}, since a derived query cannot express "equal, including when
     * both sides are null" as cleanly as a plain Java comparison.
     */
    List<VexDocument> findAllByTenantIdAndFormatAndDocumentKeyAndOriginAndActiveTrue(
            UUID tenantId, VexDocumentFormat format, String documentKey, VexOrigin origin);

    Page<VexDocument> findAllByTenantIdOrderByUploadedAtDesc(UUID tenantId, Pageable pageable);

    Page<VexDocument> findAllByTenantIdAndActiveOrderByUploadedAtDesc(UUID tenantId, boolean active, Pageable pageable);

}
