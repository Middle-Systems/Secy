package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.compliance.ComplianceControlResponse;
import net.jdesive.secy.model.compliance.ComplianceMisconfigurationResponse;
import net.jdesive.secy.model.compliance.ComplianceReportDetailResponse;
import net.jdesive.secy.model.compliance.ComplianceReportSummaryResponse;
import net.jdesive.secy.model.compliance.NormalizedComplianceReport;
import net.jdesive.secy.model.compliance.NormalizedControl;
import net.jdesive.secy.model.compliance.NormalizedMisconfiguration;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.persistence.DockerComplianceControlRepository;
import net.jdesive.secy.persistence.DockerComplianceReportMisconfigRepository;
import net.jdesive.secy.persistence.DockerComplianceReportRepository;
import net.jdesive.secy.persistence.DockerComplianceReportVulnerabilityRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.DockerComplianceControl;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.persistence.entity.DockerComplianceReportMisconfig;
import net.jdesive.secy.persistence.entity.DockerComplianceReportReference;
import net.jdesive.secy.persistence.entity.DockerComplianceReportVulnerability;
import net.jdesive.secy.persistence.entity.DockerMisconfigurationReference;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.service.compliance.CisReportParser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Persists a CIS/Docker compliance report and routes its vulnerability half into the ordinary funnel.
 *
 * <h2>The Phase 5 architecture decision</h2>
 *
 * <p>A compliance report says two things, and Phase 5 sends them two different ways.
 *
 * <p><b>Vulnerabilities go through the Phase 4 asset pipeline, unchanged.</b> The report's
 * {@code vulnerabilities[]} entries are literally {@code trivy image} findings — same package name,
 * same installed version, same {@code FixedVersion}, same CVE id — so they become
 * {@code AssetComponent}s and {@code VulnerabilityAlert}s on the audited {@link Asset} via
 * {@link AssetService#applyScan}, take the same OSV-primary/CPE-fallback correlation, get the same
 * KEV/EPSS/exploit-maturity enrichment, and appear in {@code GET /actionable} with an
 * {@code assetId}. This is the fix for the oldest known defect in the codebase: Docker/CIS
 * vulnerabilities have been outside the actionable funnel since before Phase 1, because
 * {@code DockerVulnerabilityAlert} had no join to {@code Vulnerability} and therefore no EPSS, no KEV
 * and no way to be ranked. Phase 4 already built the machinery; Phase 5 simply stops routing around
 * it. Both alert entities that shortcut the funnel have been deleted.
 *
 * <p><b>Misconfigurations stay their own concept.</b> A benchmark control has no CVE, so it has no
 * EPSS score, no KEV membership and no exploit maturity — every input the actionable funnel ranks on
 * is structurally absent. Forcing controls into {@code /actionable} would either fabricate those
 * values or permanently park a second class of unrankable row on the product's primary screen. They
 * are read through {@code GET /compliance/reports/{id}} instead, with their remediation text.
 *
 * <h2>Two transactions, the Phase 3/4 upload pattern</h2>
 *
 * <ul>
 *   <li>{@link #createPlaceholder} runs synchronously in the controller, after
 *       {@link CisReportParser} has already validated the document. It finds-or-creates the asset,
 *       creates the report row and parks the raw JSON on it, so the {@code 202} carries a real report
 *       id immediately.</li>
 *   <li>{@link #ingestScanJob} runs inside the {@code COMPLIANCE_SCAN} job: persist the benchmark
 *       half, then hand the vulnerability half to the asset pipeline.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ComplianceService {

    /** How many misconfigurations and actionable items {@code GET /compliance/reports/{id}} embeds. */
    public static final int DEFAULT_DETAIL_ITEMS = 25;

    /** {@code asset.scanner} / {@code Job} provenance for a compliance-sourced scan. */
    public static final String SCANNER_LABEL = "Trivy CIS";

    private static final int MAX_SHORT = 255;
    private static final int MAX_ID = 64;
    private static final int MAX_TARGET = 512;
    private static final int MAX_TEXT = 4096;
    private static final int MAX_LONG_TEXT = 10024;
    private static final int MAX_PATH = 1024;

    private final DockerComplianceReportRepository reportRepository;
    private final DockerComplianceControlRepository controlRepository;
    private final DockerComplianceReportMisconfigRepository misconfigRepository;
    private final DockerComplianceReportVulnerabilityRepository reportVulnerabilityRepository;
    private final VulnerabilityAlertRepository alertRepository;
    private final AssetService assetService;
    private final ActionableService actionableService;
    private final CisReportParser parser;
    private final ObjectMapper objectMapper;

    /* ------------------------------------------------------------------ */
    /* Upload                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Create the report row for an upload and park the raw document on it.
     *
     * <p>The <b>report</b> is created fresh every time while the <b>asset</b> is found-or-created:
     * a compliance report is a dated audit whose history is the point, and the asset is the running
     * thing being audited. That asymmetry is what makes "41 of 116 controls failed on the 3rd, 12 on
     * the 10th" expressible while still reconciling the vulnerability alerts in place.
     */
    @Transactional
    public DockerComplianceReport createPlaceholder(NormalizedComplianceReport parsed, AssetType type,
                                                    String assetName, Product product, String rawBody,
                                                    UUID jobId) {
        Asset asset = assetService.findOrCreate(type, assetName, product, SCANNER_LABEL, jobId);

        DockerComplianceReport report = new DockerComplianceReport();
        report.setReportId(truncate(parsed.benchmarkId(), MAX_SHORT));
        report.setTitle(truncate(parsed.title(), MAX_SHORT));
        report.setDescription(truncate(parsed.description(), MAX_TEXT));
        report.setVersion(truncate(parsed.version(), MAX_SHORT));
        report.setAsset(asset);
        report.setStatus(DockerComplianceReport.STATUS_QUEUED);
        report.setPendingRawBody(rawBody);
        report.setJobId(jobId);
        return reportRepository.saveAndFlush(report);
    }

    /**
     * Point an already-ingested report at a fresh {@code COMPLIANCE_SCAN} job.
     *
     * <p>Backs {@code POST /compliance/reports/{id}/scan}, which the roadmap replaces
     * {@code GET /cis/docker/scan/{id}} with. The raw body is long gone by then, so the re-scan
     * replays the report's own persisted vulnerability rows — see {@link #replayFindings}. Its point
     * is to re-run correlation and enrichment after a feed refresh without re-uploading the document.
     *
     * @return empty when the id is unknown
     */
    @Transactional
    public Optional<DockerComplianceReport> queueRescan(String reportId, UUID jobId) {
        return reportRepository.findById(reportId).map(report -> {
            report.setStatus(DockerComplianceReport.STATUS_QUEUED);
            report.setJobId(jobId);
            if (report.getAsset() != null) {
                report.getAsset().setJobId(jobId);
            }
            return reportRepository.saveAndFlush(report);
        });
    }

    /**
     * The real work, run inside the {@code COMPLIANCE_SCAN} job.
     *
     * @throws IllegalStateException if no report is waiting on this job
     */
    @Transactional
    public IngestResult ingestScanJob(UUID jobId, JobProgress progress) {
        DockerComplianceReport report = reportRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No compliance report is waiting on job " + jobId));

        report.setStatus(DockerComplianceReport.STATUS_PROCESSING);
        reportRepository.saveAndFlush(report);

        List<ScannedPackage> packages;
        List<ScannerFinding> findings;
        String verb;

        String rawBody = report.getPendingRawBody();
        if (rawBody != null && !rawBody.isBlank()) {
            NormalizedComplianceReport parsed = reparse(rawBody);
            persistBenchmark(report, parsed);
            report.setPendingRawBody(null);
            reportRepository.saveAndFlush(report);
            packages = parsed.packages();
            findings = parsed.findings();
            verb = "Ingested";
        } else {
            // A re-scan: the document is gone, but the rows it wrote are the same statements.
            Replay replay = replayFindings(report);
            packages = replay.packages();
            findings = replay.findings();
            verb = "Re-scanned";
        }

        progress.report(0, verb.toLowerCase() + " benchmark; correlating " + packages.size() + " packages");

        Asset asset = report.getAsset();
        if (asset == null) {
            // Not reachable through the upload path, which refuses a report it cannot name an asset
            // for. Guarded so a hand-written row can never take the whole job down.
            throw new IllegalStateException("Compliance report " + report.getId() + " has no asset to correlate against");
        }

        AssetService.ScanApplication applied = assetService.applyScan(asset, packages, findings, progress);

        LocalDateTime now = LocalDateTime.now();
        asset.setLastScannedAt(now);
        asset.setStatus(Asset.STATUS_COMPLETED);
        report.setScannedAt(now);
        report.setStatus(DockerComplianceReport.STATUS_COMPLETED);
        reportRepository.saveAndFlush(report);

        String message = String.format(
                "%s %s of %s: %d controls (%d failed, %d passed, %d not evaluated), %d checks, "
                        + "%d vulnerable packages, %d alerts raised, %d updated, %d auto-resolved",
                verb, report.getReportId() == null ? "compliance report" : report.getReportId(),
                asset.getName(), report.getTotalControls(), report.getFailedControls(),
                report.getPassedControls(), report.getSkippedControls(),
                report.getMisconfigurations().size(), applied.componentsPresent(),
                applied.correlation().created(), applied.correlation().updated(),
                applied.correlation().autoResolved());
        log.info(message);
        return IngestResult.of(report.getTotalControls() + applied.componentsPresent(), message);
    }

    /**
     * Move the report (and its asset) to {@code FAILED} after the job threw.
     *
     * <p>{@code REQUIRES_NEW} for the reason {@code AssetService.markScanJobFailed} documents: the
     * failure came from {@link #ingestScanJob} throwing, which already rolled back everything it
     * wrote, so only a separate transaction can make this stick.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markScanJobFailed(UUID jobId) {
        reportRepository.findByJobId(jobId).ifPresent(report -> {
            report.setStatus(DockerComplianceReport.STATUS_FAILED);
            report.setPendingRawBody(null);
            if (report.getAsset() != null) {
                report.getAsset().setStatus(Asset.STATUS_FAILED);
            }
            reportRepository.save(report);
        });
    }

    /* ------------------------------------------------------------------ */
    /* Persisting the benchmark half                                      */
    /* ------------------------------------------------------------------ */

    private void persistBenchmark(DockerComplianceReport report, NormalizedComplianceReport parsed) {
        for (String url : parsed.relatedResources()) {
            DockerComplianceReportReference reference = new DockerComplianceReportReference();
            reference.setUrl(truncate(url, MAX_SHORT));
            reference.setReport(report);
            report.getReferences().add(reference);
        }

        int passed = 0;
        int failed = 0;
        int skipped = 0;

        for (NormalizedControl normalizedControl : parsed.controls()) {
            DockerComplianceControl control = new DockerComplianceControl();
            control.setControlId(truncate(normalizedControl.controlId(), MAX_ID));
            control.setName(truncate(normalizedControl.name(), MAX_SHORT));
            control.setDescription(truncate(normalizedControl.description(), MAX_TEXT));
            control.setSeverity(truncate(normalizedControl.severity(), 32));
            control.setStatus(normalizedControl.status());
            control.setFailedChecks(normalizedControl.failedChecks());
            control.setReport(report);
            report.getControls().add(control);

            switch (normalizedControl.status()) {
                case PASS -> passed++;
                case FAIL -> failed++;
                case SKIP -> skipped++;
            }

            for (NormalizedMisconfiguration check : normalizedControl.checks()) {
                DockerComplianceReportMisconfig misconfig = new DockerComplianceReportMisconfig();
                misconfig.setType(truncate(check.type(), MAX_SHORT));
                misconfig.setCheckId(truncate(check.checkId(), MAX_ID));
                misconfig.setAvdId(truncate(check.avdId(), MAX_SHORT));
                misconfig.setTitle(truncate(check.title(), MAX_SHORT));
                misconfig.setDescription(truncate(check.description(), MAX_LONG_TEXT));
                misconfig.setMessage(truncate(check.message(), MAX_TEXT));
                misconfig.setResolution(truncate(check.resolution(), MAX_TEXT));
                misconfig.setSeverity(truncate(check.severity(), MAX_SHORT));
                misconfig.setStatus(check.status());
                misconfig.setTarget(truncate(check.target(), MAX_TARGET));
                misconfig.setPrimaryUrl(truncate(check.primaryUrl(), MAX_SHORT));
                misconfig.setControl(control);
                misconfig.setReport(report);
                for (String url : check.references()) {
                    DockerMisconfigurationReference reference = new DockerMisconfigurationReference();
                    reference.setUrl(truncate(url, MAX_SHORT));
                    reference.setReport(misconfig);
                    misconfig.getReferences().add(reference);
                }
                control.getMisconfigurations().add(misconfig);
                report.getMisconfigurations().add(misconfig);
            }
        }

        report.setPassedControls(passed);
        report.setFailedControls(failed);
        report.setSkippedControls(skipped);

        // The report's own record of its vulnerability section. Evidence + re-scan input; the alerts
        // themselves live on the asset.
        for (ScannerFinding finding : parsed.findings()) {
            ScannedPackage pkg = finding.pkg();
            NormalizedComponent component = pkg.component();
            DockerComplianceReportVulnerability row = new DockerComplianceReportVulnerability();
            row.setVulnerabilityId(truncate(finding.cveId(), MAX_ID));
            row.setPackageName(truncate(component.name(), MAX_SHORT));
            row.setVersion(truncate(component.version(), MAX_SHORT));
            row.setFixVersion(truncate(finding.fix() == null ? null : finding.fix().versions(), MAX_SHORT));
            row.setPurl(truncate(component.purl(), MAX_TARGET));
            row.setPackageType(truncate(component.type(), MAX_ID));
            row.setTarget(truncate(pkg.scanTarget(), MAX_TARGET));
            row.setPackagePath(truncate(pkg.packagePath(), MAX_PATH));
            row.setLayer(truncate(pkg.layer(), MAX_SHORT));
            row.setReport(report);
            report.getVulnerabilities().add(row);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Re-scan replay                                                     */
    /* ------------------------------------------------------------------ */

    private record Replay(List<ScannedPackage> packages, List<ScannerFinding> findings) {
    }

    /**
     * Rebuild the scan input from the report's persisted vulnerability rows.
     *
     * <p>Exact rather than approximate: the PURL and the scanner {@code Type} are stored on each row
     * precisely so the reconstructed {@code identityKey} is the same string the original ingest
     * produced. If it were re-derived by guesswork, a re-scan would present "new" components and
     * auto-resolve every alert the upload had raised.
     */
    private Replay replayFindings(DockerComplianceReport report) {
        Map<String, ScannedPackage> packages = new java.util.LinkedHashMap<>();
        List<ScannerFinding> findings = new ArrayList<>();

        for (DockerComplianceReportVulnerability row : reportVulnerabilityRepository.findAllByReportId(report.getId())) {
            if (row.getVulnerabilityId() == null || row.getPackageName() == null) {
                continue;
            }
            NormalizedComponent component = NormalizedComponent.builder()
                    .name(row.getPackageName())
                    .version(row.getVersion())
                    .purl(row.getPurl())
                    .type(row.getPackageType())
                    .build();
            ScannedPackage scanned = new ScannedPackage(component, AssetComponentSource.TRIVY,
                    row.getTarget(), row.getPackagePath(), row.getLayer());
            if (scanned.identityKey() == null) {
                continue;
            }
            ScannedPackage existing = packages.putIfAbsent(scanned.identityKey(), scanned);
            FixResolution fix = row.getFixVersion() == null || row.getFixVersion().isBlank()
                    ? null
                    : FixResolution.fixed(row.getFixVersion(), FixSource.SCANNER);
            findings.add(new ScannerFinding(existing == null ? scanned : existing,
                    row.getVulnerabilityId(), fix));
        }
        return new Replay(List.copyOf(packages.values()), findings);
    }

    /* ------------------------------------------------------------------ */
    /* Reads                                                              */
    /* ------------------------------------------------------------------ */

    /** {@code GET /compliance/reports} — paged, newest first, optionally narrowed to one asset. */
    @Transactional(readOnly = true)
    public Page<ComplianceReportSummaryResponse> list(int page, int size, UUID assetId) {
        Page<DockerComplianceReport> reports = reportRepository.search(assetId, PageRequest.of(page, size));
        List<UUID> assetIds = reports.getContent().stream()
                .map(DockerComplianceReport::getAsset)
                .filter(java.util.Objects::nonNull)
                .map(Asset::getId)
                .distinct()
                .toList();

        // One grouped query for the whole page rather than one per row — same reasoning as
        // AssetService.list.
        Map<UUID, Long> actionable = assetIds.isEmpty()
                ? Map.of()
                : tally(alertRepository.countActionableByAsset(assetIds));

        return reports.map(report -> ComplianceReportSummaryResponse.of(report,
                report.getAsset() == null ? 0L : actionable.getOrDefault(report.getAsset().getId(), 0L)));
    }

    /** {@code GET /compliance/reports/{id}} — both halves, each paged where it needs to be. */
    @Transactional(readOnly = true)
    public Optional<ComplianceReportDetailResponse> findDetail(String id, int misconfigPage, int misconfigSize,
                                                               ComplianceStatus misconfigStatus,
                                                               int itemsPage, int itemsSize) {
        return reportRepository.findById(id).map(report -> ComplianceReportDetailResponse.of(
                report,
                controlRepository.findAllByReportIdOrderByControlIdAsc(id).stream()
                        .map(ComplianceControlResponse::of)
                        .toList(),
                findMisconfigurations(id, misconfigPage, misconfigSize, misconfigStatus),
                actionableItems(report, itemsPage, itemsSize)));
    }

    /** {@code GET /compliance/reports/{id}/misconfigurations} — the same page, on its own. */
    @Transactional(readOnly = true)
    public Page<ComplianceMisconfigurationResponse> findMisconfigurations(String reportId, int page, int size,
                                                                          ComplianceStatus status) {
        return misconfigRepository.findForReport(reportId, status, PageRequest.of(page, size))
                .map(ComplianceMisconfigurationResponse::of);
    }

    /** Whether a report exists, without loading its graph. */
    @Transactional(readOnly = true)
    public boolean exists(String reportId) {
        return reportRepository.existsById(reportId);
    }

    private Page<ActionableItemResponse> actionableItems(DockerComplianceReport report, int page, int size) {
        if (report.getAsset() == null) {
            return Page.empty(PageRequest.of(page, size));
        }
        return actionableService.findActionableForAsset(page, size, report.getAsset().getId());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private NormalizedComplianceReport reparse(String rawBody) {
        JsonNode root;
        try {
            root = objectMapper.readTree(rawBody);
        } catch (IOException e) {
            // The controller already validated this exact document once; this only fires if the
            // stashed text were corrupted at rest.
            throw new IllegalStateException("Stashed compliance report failed to re-parse as JSON: "
                    + e.getMessage(), e);
        }
        return parser.parse(root);
    }

    private static Map<UUID, Long> tally(List<Object[]> rows) {
        Map<UUID, Long> counts = new HashMap<>();
        for (Object[] row : rows) {
            counts.put((UUID) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    /** Ingest hardening, same rule as the SBOM and asset paths: clip rather than fail the upload. */
    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
