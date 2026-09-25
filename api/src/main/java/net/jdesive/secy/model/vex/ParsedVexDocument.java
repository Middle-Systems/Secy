package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexDocumentFormat;

import java.time.LocalDateTime;
import java.util.List;

/**
 * A VEX document, normalized by one of the pure {@code net.jdesive.secy.service.vex.parser} parsers.
 * Not yet persisted — {@code VexIngestionService} maps this onto {@code VexDocument}/{@code VexStatement}.
 *
 * @param documentKey nullable — falls back to {@code "sha256:" + contentSha256} when the document
 *                    itself declares no identity
 * @param skippedCount statements the parser recognised but could not emit (see each statement's
 *                     warning) — distinct from statements silently absent from the source document
 */
public record ParsedVexDocument(
        VexDocumentFormat format,
        String specVersion,
        String documentKey,
        String documentVersion,
        String author,
        LocalDateTime documentTimestamp,
        List<ParsedVexStatement> statements,
        List<String> warnings,
        int skippedCount) {
}
