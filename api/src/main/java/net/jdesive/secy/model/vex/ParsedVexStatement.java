package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;

/**
 * One normalized VEX assertion, emitted by a format parser. {@code targetPurl}/{@code matchVersion}
 * are already PURL-derived; a parser that could not resolve a usable PURL still emits this record
 * (with both null) plus a warning on the owning {@link ParsedVexDocument}, so the statement is stored
 * unmatchable rather than dropped — "flag, don't guess" (M1c's rule, carried into M1f).
 *
 * @param aliases   other vulnerability ids the source document listed alongside {@code cveId}
 * @param timestamp this statement's own timestamp, or null to fall back to the document's, then to
 *                  ingestion time
 */
public record ParsedVexStatement(
        String cveId,
        java.util.List<String> aliases,
        VexStatus status,
        String sourceStatus,
        VexJustification justification,
        String sourceJustification,
        String impactStatement,
        String actionStatement,
        String productRef,
        String targetPurl,
        String targetCpe,
        String matchVersion,
        LocalDateTime timestamp,
        int ordinal) {
}
