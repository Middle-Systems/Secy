package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/** Every {@link VexStatement} field except {@code tenantId} and {@code authorKey} (an internal grouping key). */
public record VexStatementResponse(
        UUID id,
        UUID documentId,
        VexDocumentFormat format,
        VexOrigin origin,
        UUID scopeProductId,
        String author,
        boolean active,
        String cveId,
        String vulnerabilityAliases,
        VexStatus status,
        String sourceStatus,
        VexJustification justification,
        String sourceJustification,
        String impactStatement,
        String actionStatement,
        String productRef,
        String targetPurl,
        String targetCpe,
        String matchKey,
        String matchVersion,
        LocalDateTime statementTimestamp,
        int ordinal,
        LocalDateTime createdAt) {

    public static VexStatementResponse from(VexStatement s) {
        return new VexStatementResponse(s.getId(), s.getDocumentId(), s.getFormat(), s.getOrigin(),
                s.getScopeProductId(), s.getAuthor(), s.isActive(), s.getCveId(), s.getVulnerabilityAliases(),
                s.getStatus(), s.getSourceStatus(), s.getJustification(), s.getSourceJustification(),
                s.getImpactStatement(), s.getActionStatement(), s.getProductRef(), s.getTargetPurl(),
                s.getTargetCpe(), s.getMatchKey(), s.getMatchVersion(), s.getStatementTimestamp(), s.getOrdinal(),
                s.getCreatedAt());
    }

}
