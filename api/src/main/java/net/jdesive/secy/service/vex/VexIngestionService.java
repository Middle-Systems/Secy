package net.jdesive.secy.service.vex;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexDocumentStatus;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.service.vex.VexResolutionService.VexReconcileSummary;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Persists parsed VEX documents and their statements, handles same-document-key supersession, and
 * triggers reconciliation — the {@code VEX_UPLOAD} job's actual work (see {@code VexIngestJobService}
 * for the thin non-transactional orchestrator that calls this and {@link #markUploadJobFailed}).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VexIngestionService {

    private final VexDocumentRepository vexDocumentRepository;

    private final VexStatementRepository vexStatementRepository;

    private final VexDocumentParser vexDocumentParser;

    private final VexResolutionService vexResolutionService;

    /**
     * Creates the placeholder row {@code POST /vex} hands back a job for. The document has already
     * been fully parsed and validated synchronously by the controller — this only persists what it
     * found, plus the raw body for the job to re-parse.
     */
    @Transactional
    public VexDocument createPlaceholder(ParsedVexDocument parsed, byte[] rawBody, VexOrigin origin,
                                         UUID scopeProductId, UUID jobId) {
        String sha256 = sha256Hex(rawBody);
        VexDocument document = new VexDocument();
        // TODO(tenancy-hardening): no request-scoped tenant context yet; every VEX row lands here.
        document.setTenantId(Tenant.DEFAULT_TENANT_ID);
        document.setFormat(parsed.format());
        document.setSpecVersion(truncate(parsed.specVersion(), 32));
        String documentKey = parsed.documentKey() != null && !parsed.documentKey().isBlank()
                ? parsed.documentKey() : "sha256:" + sha256;
        document.setDocumentKey(truncate(documentKey, 1024));
        document.setDocumentVersion(truncate(parsed.documentVersion(), 64));
        document.setAuthor(truncate(parsed.author(), 512));
        document.setOrigin(origin);
        document.setScopeProductId(scopeProductId);
        document.setDocumentTimestamp(parsed.documentTimestamp());
        document.setStatus(VexDocumentStatus.QUEUED);
        document.setJobId(jobId);
        document.setPendingRawBody(new String(rawBody, StandardCharsets.UTF_8));
        document.setContentSha256(sha256);
        document.setActive(false);
        document.setStatementCount(0);
        document.setSkippedCount(0);
        return vexDocumentRepository.saveAndFlush(document);
    }

    /**
     * The job's actual work, all in one transaction — unlike {@code SbomIngestJobService}'s
     * after-commit event, VEX has no cross-document ordering dependency, so making the whole document
     * (persist statements, supersede the previous document, reconcile alerts) all-or-nothing is
     * strictly better: a failed reconcile fails the job and rolls the whole document back rather than
     * leaving half-persisted statements behind.
     *
     * <p><b>Known race:</b> a concurrent correlation transaction may read statements before this
     * commits and write a stale snapshot onto an alert. It self-heals on the next correlation of that
     * scope, the next VEX upload for that CVE, or {@code POST /vex/reconcile}.
     */
    @Transactional
    public IngestResult ingestUploadJob(UUID jobId, JobProgress progress) {
        VexDocument document = vexDocumentRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No VEX document row is waiting on upload job " + jobId));

        document.setStatus(VexDocumentStatus.PROCESSING);
        vexDocumentRepository.saveAndFlush(document);

        String rawBody = document.getPendingRawBody();
        if (rawBody == null) {
            throw new IllegalStateException("VEX document " + document.getId() + " has no pending raw body to ingest");
        }
        ParsedVexDocument parsed = vexDocumentParser.parse(rawBody.getBytes(StandardCharsets.UTF_8));

        List<VexStatement> statements = new ArrayList<>();
        Set<String> newCveIds = new LinkedHashSet<>();
        for (ParsedVexStatement p : parsed.statements()) {
            VexStatement statement = new VexStatement();
            statement.setTenantId(document.getTenantId());
            statement.setDocumentId(document.getId());
            statement.setFormat(document.getFormat());
            statement.setOrigin(document.getOrigin());
            statement.setScopeProductId(document.getScopeProductId());
            statement.setAuthor(document.getAuthor());
            statement.setAuthorKey(authorKey(document));
            statement.setActive(true);
            statement.setCveId(truncate(p.cveId(), 64));
            statement.setVulnerabilityAliases(truncate(joinAliases(p), 1024));
            statement.setStatus(p.status());
            statement.setSourceStatus(truncate(p.sourceStatus(), 64));
            statement.setJustification(p.justification());
            statement.setSourceJustification(truncate(p.sourceJustification(), 128));
            statement.setImpactStatement(truncate(p.impactStatement(), 4096));
            statement.setActionStatement(truncate(p.actionStatement(), 4096));
            statement.setProductRef(truncate(Objects.requireNonNullElse(p.productRef(), ""), 1024));
            statement.setTargetPurl(truncate(p.targetPurl(), 1024));
            statement.setTargetCpe(truncate(p.targetCpe(), 1024));
            statement.setMatchKey(truncate(p.targetPurl() == null ? null : matchKeyOf(p), 512));
            statement.setMatchVersion(truncate(p.matchVersion(), 255));
            LocalDateTime timestamp = p.timestamp() != null ? p.timestamp()
                    : document.getDocumentTimestamp() != null ? document.getDocumentTimestamp() : LocalDateTime.now();
            statement.setStatementTimestamp(timestamp);
            statement.setOrdinal(p.ordinal());
            statements.add(statement);
            newCveIds.add(statement.getCveId());
        }

        List<VexDocument> superseded = findSupersessionCandidates(document);
        Set<String> supersededCveIds = new LinkedHashSet<>();
        for (VexDocument old : superseded) {
            supersededCveIds.addAll(vexStatementRepository.findDistinctCveIdsByDocumentId(old.getId()));
            old.setActive(false);
            old.setDeactivatedAt(LocalDateTime.now());
            old.setSupersededById(document.getId());
            vexStatementRepository.deactivateAllByDocumentId(old.getId());
        }
        if (!superseded.isEmpty()) {
            vexDocumentRepository.saveAll(superseded);
        }

        vexStatementRepository.saveAll(statements);

        document.setActive(true);
        document.setStatus(VexDocumentStatus.COMPLETED);
        document.setProcessedAt(LocalDateTime.now());
        document.setStatementCount(parsed.statements().size());
        document.setSkippedCount(parsed.skippedCount());
        document.setWarnings(truncate(joinWarnings(parsed.warnings()), 4096));
        document.setPendingRawBody(null);
        vexDocumentRepository.saveAndFlush(document);

        Set<String> toReconcile = new LinkedHashSet<>(newCveIds);
        toReconcile.addAll(supersededCveIds);
        VexReconcileSummary summary = vexResolutionService.reconcileCves(document.getTenantId(), toReconcile);

        progress.report(statements.size(), "Persisted " + statements.size() + " VEX statements; re-evaluated "
                + summary.alertsEvaluated() + " alerts (" + summary.alertsChanged() + " changed)");

        return new IngestResult(statements.size(), "Ingested " + statements.size() + " " + document.getFormat()
                + " VEX statements (" + parsed.skippedCount() + " skipped); re-evaluated " + summary.alertsEvaluated()
                + " alerts, " + summary.alertsChanged() + " changed");
    }

    /**
     * Runs in a fresh transaction: the failure came from {@link #ingestUploadJob} throwing, which
     * already rolled its own transaction (and everything written inside it) back.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markUploadJobFailed(UUID jobId) {
        vexDocumentRepository.findByJobId(jobId).ifPresent(document -> {
            document.setStatus(VexDocumentStatus.FAILED);
            document.setPendingRawBody(null);
            document.setActive(false);
            vexDocumentRepository.save(document);
        });
    }

    /** Deactivates a document and its statements, then reconciles every CVE it touched. Idempotent. Never deletes. */
    @Transactional
    public VexDocument deactivate(UUID documentId) {
        VexDocument document = vexDocumentRepository.findById(documentId)
                .orElseThrow(() -> new VexDocumentNotFoundException(documentId));
        List<String> cveIds = vexStatementRepository.findDistinctCveIdsByDocumentId(documentId);
        document.setActive(false);
        document.setDeactivatedAt(LocalDateTime.now());
        vexDocumentRepository.save(document);
        vexStatementRepository.deactivateAllByDocumentId(documentId);
        vexResolutionService.reconcileCves(document.getTenantId(), new LinkedHashSet<>(cveIds));
        return document;
    }

    /* ------------------------------------------------------------------ */

    private List<VexDocument> findSupersessionCandidates(VexDocument document) {
        return vexDocumentRepository.findAllByTenantIdAndFormatAndDocumentKeyAndOriginAndActiveTrue(
                        document.getTenantId(), document.getFormat(), document.getDocumentKey(), document.getOrigin())
                .stream()
                .filter(candidate -> !candidate.getId().equals(document.getId()))
                .filter(candidate -> Objects.equals(candidate.getScopeProductId(), document.getScopeProductId()))
                .toList();
    }

    private static String authorKey(VexDocument document) {
        String author = document.getAuthor();
        if (author != null && !author.isBlank()) {
            return truncate(author.trim().toLowerCase(java.util.Locale.ROOT), 1024);
        }
        return truncate("document:" + document.getDocumentKey(), 1024);
    }

    /** Recomputes a match key straight off a parsed statement's own target PURL — no re-parsing. */
    private static String matchKeyOf(ParsedVexStatement p) {
        return net.jdesive.secy.model.component.ComponentIdentity.keyOf(p.targetPurl(), null);
    }

    private static String joinAliases(ParsedVexStatement p) {
        if (p.aliases() == null || p.aliases().isEmpty()) {
            return null;
        }
        return String.join(",", p.aliases());
    }

    private static String joinWarnings(List<String> warnings) {
        if (warnings == null || warnings.isEmpty()) {
            return null;
        }
        List<String> first50 = warnings.size() > 50 ? warnings.subList(0, 50) : warnings;
        return String.join("\n", first50);
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private static String sha256Hex(byte[] body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(body));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

}
