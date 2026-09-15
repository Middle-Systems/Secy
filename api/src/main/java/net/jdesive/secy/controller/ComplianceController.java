package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.compliance.ComplianceMisconfigurationResponse;
import net.jdesive.secy.model.compliance.ComplianceReportDetailResponse;
import net.jdesive.secy.model.compliance.ComplianceReportSummaryResponse;
import net.jdesive.secy.model.compliance.NormalizedComplianceReport;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.service.ComplianceService;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.compliance.CisReportParser;
import net.jdesive.secy.service.compliance.UnsupportedComplianceReportException;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.UUID;

/**
 * The Compliance view's endpoints: what a benchmark said about what you run.
 *
 * <h2>What replaced {@code /cis/docker/*} (Phase 5)</h2>
 *
 * <ul>
 *   <li>{@code POST /cis/docker/ingest} → {@code POST /compliance/reports}. The old endpoint parsed
 *       and persisted synchronously and returned the entity graph; this one validates synchronously,
 *       queues a {@code COMPLIANCE_SCAN} job and returns {@code 202} + the {@link Job} to poll — the
 *       Phase 3/4 upload contract, unchanged.</li>
 *   <li>{@code GET /cis/docker/scan/{id}} → {@code POST /compliance/reports/{id}/scan}. A {@code GET}
 *       that generates alerts was never safe to retry or cache; and more importantly it was a
 *       <em>mandatory second step</em>, so a report ingested and never scanned was a silently dead
 *       row. Ingest now scans in the same job, and this endpoint becomes what a re-scan should
 *       be: re-run correlation and enrichment over an existing report after a feed refresh.</li>
 * </ul>
 *
 * <h2>Why one upload+scan job rather than the old two steps</h2>
 *
 * <p>The two-step design predates the job queue. Keeping it would mean a client has to make two
 * calls to get any alerts, with a stored-but-meaningless report if it stops after the first — and it
 * would be the only ingest in Secy that works that way, against {@code POST /sbom/{id}/sboms} and
 * {@code POST /assets/scan/*} which both do everything in one queued job. One POST, one job, one
 * thing to poll.
 */
@Slf4j
@Tag(name = "Compliance", description = "CIS/Docker benchmark reports: control pass-fail, misconfigurations with remediation, and the vulnerability alerts they raise")
@RestController
@RequestMapping("/compliance")
@RequiredArgsConstructor
public class ComplianceController {

    private final ComplianceService complianceService;
    private final ProductService productService;
    private final CisReportParser parser;
    private final JobService jobService;

    /* ------------------------------------------------------------------ */
    /* Upload                                                             */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Ingest a `trivy --compliance` report; validates synchronously, then queues persist + correlation as a background job",
            description = "Returns immediately with a QUEUED COMPLIANCE_SCAN job; poll GET /jobs/{id} for progress. "
                    + "The report's vulnerability half becomes ordinary asset components and vulnerability "
                    + "alerts on the audited asset, so it reaches GET /actionable like any other scan; its "
                    + "misconfiguration half stays a compliance concept and is read from "
                    + "GET /compliance/reports/{id}. The asset is created if (type, name) is new and updated "
                    + "in place otherwise, so re-auditing the same image reconciles its alerts rather than "
                    + "duplicating them. Every upload creates a NEW report row — a compliance report is a "
                    + "dated audit and the history is the point.")
    @ApiResponse(responseCode = "202", description = "Report validated; ingest queued")
    @ApiResponse(responseCode = "400", description = "Body is not a Trivy compliance report, or no asset name could be determined")
    @PostMapping(value = "/reports", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> upload(
            @Parameter(description = "Name of the asset this report audited. Required unless the document "
                    + "names one itself (most `--compliance` runs do not), in which case its ArtifactName "
                    + "or first scanned Target is used.")
            @RequestParam(required = false) String name,
            @RequestParam(defaultValue = "CONTAINER_IMAGE") AssetType type,
            @Parameter(description = "Optional product this asset belongs to")
            @RequestParam(required = false) UUID productId,
            @RequestBody JsonNode body,
            Principal principal) {

        // 1. Parse and validate. Throws UnsupportedComplianceReportException -> 400. The only
        //    synchronous work, and the only thing that can reject the upload outright.
        NormalizedComplianceReport parsed = parser.parse(body);

        // 2. Resolve what was audited. Unlike `trivy image`, a compliance document usually carries no
        //    artifact identity at all, so the caller must supply one when it does not — a compliance
        //    report with no subject is unreadable, and guessing a name would be worse than asking.
        String assetName = firstNonBlank(name, parsed.artifactName());
        if (assetName == null) {
            throw new UnsupportedComplianceReportException(
                    "No asset name: this compliance report does not name what it audited, so the `name` "
                            + "request parameter is required.");
        }

        Product product = productId == null ? null : productService.getProductById(productId);

        // 3. Queue the job, then create the report row pointing at it. Same ordering as the SBOM and
        //    asset uploads: the job row has to exist before the domain row can cite its id.
        Job job = jobService.create(JobType.COMPLIANCE_SCAN, principal);
        DockerComplianceReport report = complianceService.createPlaceholder(
                parsed, type, assetName, product, body.toString(), job.getId());

        log.info("Queued compliance report {} ({}) for {} asset {} as job {}: {} controls, {} findings pending ingest",
                report.getId(), parsed.benchmarkId(), type, assetName, job.getId(),
                parsed.controls().size(), parsed.findings().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    @Operation(summary = "Re-scan an already-ingested report",
            description = "Queues a COMPLIANCE_SCAN job that replays the report's persisted findings "
                    + "through correlation and enrichment again — use it after a KEV/EPSS/OSV refresh to "
                    + "re-evaluate the funnel for the audited asset without re-uploading the document. "
                    + "Replaces the old GET /cis/docker/scan/{id}.")
    @ApiResponse(responseCode = "202", description = "Re-scan queued")
    @ApiResponse(responseCode = "404", description = "No report with that id")
    @PostMapping("/reports/{id}/scan")
    public ResponseEntity<Job> rescan(@PathVariable String id, Principal principal) {
        if (!complianceService.exists(id)) {
            return ResponseEntity.notFound().build();
        }
        Job job = jobService.create(JobType.COMPLIANCE_SCAN, principal);
        return complianceService.queueRescan(id, job.getId())
                .map(report -> new ResponseEntity<>(job, HttpStatus.ACCEPTED))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /* ------------------------------------------------------------------ */
    /* Reads                                                              */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "List compliance reports, newest first",
            description = "Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed). "
                    + "Each row carries its control pass/fail/skip counts and the audited asset's count of "
                    + "ACTIVE actionable alerts — the same predicate GET /actionable applies.")
    @GetMapping("/reports")
    public Page<ComplianceReportSummaryResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @Parameter(description = "Only reports audited against this asset")
            @RequestParam(required = false) UUID assetId) {
        return complianceService.list(page, size, assetId);
    }

    @Operation(summary = "One report: control pass/fail summary, paged misconfigurations with remediation, and paged vulnerability alerts",
            description = "`controls` is the full per-control breakdown; `misconfigurations` is a page of "
                    + "checks, failures first, each with its `resolution` remediation text; "
                    + "`actionableItems` is a page of the same ActionableItemResponse rows GET /actionable "
                    + "returns, filtered to the audited asset and sorted the same way.")
    @ApiResponse(responseCode = "404", description = "No report with that id")
    @GetMapping("/reports/{id}")
    public ResponseEntity<ComplianceReportDetailResponse> detail(
            @PathVariable String id,
            @RequestParam(defaultValue = "0") int misconfigPage,
            @RequestParam(required = false) Integer misconfigSize,
            @Parameter(description = "Only checks with this verdict: PASS / FAIL / SKIP")
            @RequestParam(required = false) ComplianceStatus misconfigStatus,
            @RequestParam(defaultValue = "0") int itemsPage,
            @RequestParam(required = false) Integer itemsSize) {
        return complianceService.findDetail(id,
                        misconfigPage, misconfigSize == null ? ComplianceService.DEFAULT_DETAIL_ITEMS : misconfigSize,
                        misconfigStatus,
                        itemsPage, itemsSize == null ? ComplianceService.DEFAULT_DETAIL_ITEMS : itemsSize)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "A report's misconfigurations, paged on their own",
            description = "The same page GET /compliance/reports/{id} embeds, for paging deeper without "
                    + "re-fetching the whole report.")
    @ApiResponse(responseCode = "404", description = "No report with that id")
    @GetMapping("/reports/{id}/misconfigurations")
    public ResponseEntity<Page<ComplianceMisconfigurationResponse>> misconfigurations(
            @PathVariable String id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) ComplianceStatus status) {
        if (!complianceService.exists(id)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(complianceService.findMisconfigurations(id, page, size, status));
    }

    /** An unreadable report is the client's problem, and the message says exactly what was wrong. */
    @ExceptionHandler(UnsupportedComplianceReportException.class)
    public ResponseEntity<ErrorResponse> onUnsupportedFormat(UnsupportedComplianceReportException e) {
        log.warn("Rejected compliance report upload: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        return b != null && !b.isBlank() ? b.trim() : null;
    }

}
