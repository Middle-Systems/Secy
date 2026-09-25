package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexDocumentStatus;
import net.jdesive.secy.persistence.entity.VexOrigin;

import java.time.LocalDateTime;
import java.util.UUID;

/** Every {@link VexDocument} field except {@code pendingRawBody} (never serialized) and {@code tenantId}. */
public record VexDocumentResponse(
        UUID id,
        VexDocumentFormat format,
        String specVersion,
        String documentKey,
        String documentVersion,
        String author,
        VexOrigin origin,
        UUID scopeProductId,
        LocalDateTime documentTimestamp,
        VexDocumentStatus status,
        UUID jobId,
        String contentSha256,
        boolean active,
        UUID supersededById,
        int statementCount,
        int skippedCount,
        String warnings,
        LocalDateTime uploadedAt,
        LocalDateTime processedAt,
        LocalDateTime deactivatedAt) {

    public static VexDocumentResponse from(VexDocument d) {
        return new VexDocumentResponse(d.getId(), d.getFormat(), d.getSpecVersion(), d.getDocumentKey(),
                d.getDocumentVersion(), d.getAuthor(), d.getOrigin(), d.getScopeProductId(), d.getDocumentTimestamp(),
                d.getStatus(), d.getJobId(), d.getContentSha256(), d.isActive(), d.getSupersededById(),
                d.getStatementCount(), d.getSkippedCount(), d.getWarnings(), d.getUploadedAt(), d.getProcessedAt(),
                d.getDeactivatedAt());
    }

}
