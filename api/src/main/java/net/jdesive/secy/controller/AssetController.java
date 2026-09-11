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
import net.jdesive.secy.model.asset.AssetDeletionSummary;
import net.jdesive.secy.model.asset.AssetDetailResponse;
import net.jdesive.secy.model.asset.AssetSummaryResponse;
import net.jdesive.secy.model.asset.NormalizedScan;
import net.jdesive.secy.model.asset.ScanFormat;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.service.AssetService;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.asset.AssetScanParser;
import net.jdesive.secy.service.asset.UnsupportedScanFormatException;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * The Infrastructure view's endpoints: what you run, and what is wrong with it.
 *
 * <h2>Scan upload mirrors SBOM upload exactly</h2>
 *
 * <p>Validate synchronously → create a placeholder row → enqueue a job → {@code 202} with the
 * {@link Job} to poll. A document that is not the scanner report the endpoint names is a plain
 * {@code 400} with nothing stored and nothing queued, for the reason Phase 3 fixed: a client must
 * never be handed a {@code 202} for work that can never succeed.
 *
 * <p>One endpoint per scanner rather than one endpoint that sniffs, because the caller always knows
 * which tool it ran, and posting Grype output to the Trivy endpoint is a mistake worth naming.
 */
@Slf4j
@Tag(name = "Assets", description = "Infrastructure inventory: container images, hosts and services, and the scanner output that describes them")
@RestController
@RequestMapping("/assets")
@RequiredArgsConstructor
public class AssetController {

    private final AssetService assetService;
    private final ProductService productService;
    private final AssetScanParser scanParser;
    private final JobService jobService;

    /* ------------------------------------------------------------------ */
    /* Scan ingest                                                        */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Ingest a `trivy image -f json` report; validates synchronously, then queues ingest + correlation as a background job",
            description = "Returns immediately with a QUEUED ASSET_SCAN job; poll GET /jobs/{id} for progress. "
                    + "Creates the asset if (type, name) is new and updates it in place otherwise, so "
                    + "re-scanning the same image reconciles its existing alerts rather than duplicating them. "
                    + "Note this is the vulnerability report, not a `trivy config` / compliance report.")
    @ApiResponse(responseCode = "202", description = "Report validated; ingest queued")
    @ApiResponse(responseCode = "400", description = "Body is not a Trivy vulnerability report, or no asset name could be determined")
    @PostMapping(value = "/scan/trivy", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> scanTrivy(
            @Parameter(description = "Asset name; defaults to the report's own ArtifactName")
            @RequestParam(required = false) String name,
            @RequestParam(defaultValue = "CONTAINER_IMAGE") AssetType type,
            @Parameter(description = "Optional product this asset belongs to")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "CPEs to declare for this asset (repeatable), for the OS/firmware case no package manager enumerates")
            @RequestParam(required = false) List<String> declaredCpe,
            @RequestBody JsonNode body,
            Principal principal) {
        return accept(ScanFormat.TRIVY, name, type, productId, declaredCpe, body, principal);
    }

    @Operation(summary = "Ingest a `grype -o json` report; validates synchronously, then queues ingest + correlation as a background job",
            description = "Same contract as the Trivy endpoint. Grype emits a PURL per artifact, so its "
                    + "language packages take the OSV-primary correlation path directly.")
    @ApiResponse(responseCode = "202", description = "Report validated; ingest queued")
    @ApiResponse(responseCode = "400", description = "Body is not a Grype report, or no asset name could be determined")
    @PostMapping(value = "/scan/grype", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> scanGrype(
            @Parameter(description = "Asset name; defaults to the report's own scan target")
            @RequestParam(required = false) String name,
            @RequestParam(defaultValue = "CONTAINER_IMAGE") AssetType type,
            @Parameter(description = "Optional product this asset belongs to")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "CPEs to declare for this asset (repeatable), for the OS/firmware case no package manager enumerates")
            @RequestParam(required = false) List<String> declaredCpe,
            @RequestBody JsonNode body,
            Principal principal) {
        return accept(ScanFormat.GRYPE, name, type, productId, declaredCpe, body, principal);
    }

    private ResponseEntity<Job> accept(ScanFormat format, String name, AssetType type, UUID productId,
                                       List<String> declaredCpes, JsonNode body, Principal principal) {
        // 1. Parse and validate. Throws UnsupportedScanFormatException -> 400. The only synchronous
        //    work, and the only thing that can reject the upload outright.
        NormalizedScan scan = scanParser.parse(format, body);

        // 2. Resolve the asset's name. The scanner usually knows it; the caller may override, and
        //    must supply one when the report carries none (a `grype dir:.` of an unnamed path).
        String assetName = firstNonBlank(name, scan.artifactName());
        if (assetName == null) {
            throw new UnsupportedScanFormatException(
                    "No asset name: the " + format.label() + " report does not name what it scanned, so "
                            + "the `name` request parameter is required.");
        }

        Product product = productId == null ? null : productService.getProductById(productId);

        // 3. Queue the job, then create/update the asset row pointing at it. Same ordering as the
        //    SBOM upload: the job row has to exist before the domain row can cite its id.
        Job job = jobService.create(JobType.ASSET_SCAN, principal);
        Asset asset = assetService.createPlaceholder(type, assetName, product, format,
                toSet(declaredCpes), body.toString(), job.getId());

        log.info("Queued {} scan of {} asset {} ({}) as job {}: {} packages, {} findings pending ingest",
                format.label(), type, asset.getId(), assetName, job.getId(),
                scan.packages().size(), scan.findings().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    /* ------------------------------------------------------------------ */
    /* Reads                                                              */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "List assets, paged and filtered",
            description = "Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed), "
                    + "ordered by name. Each row carries its current component count and its count of "
                    + "ACTIVE actionable alerts — the same predicate GET /actionable applies.")
    @GetMapping
    public Page<AssetSummaryResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @Parameter(description = "CONTAINER_IMAGE / HOST / SERVICE")
            @RequestParam(required = false) AssetType type,
            @Parameter(description = "Only assets linked to this product")
            @RequestParam(required = false) UUID productId) {
        return assetService.list(page, size, type, productId);
    }

    @Operation(summary = "One asset, with its actionable items",
            description = "`actionableItems` is a page of the same ActionableItemResponse rows "
                    + "GET /actionable returns, filtered to this asset and sorted the same way.")
    @ApiResponse(responseCode = "404", description = "No asset with that id")
    @GetMapping("/{id}")
    public ResponseEntity<AssetDetailResponse> detail(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(required = false) Integer size) {
        return assetService.findDetail(id, page, size == null ? AssetService.DEFAULT_DETAIL_ITEMS : size)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "Delete an asset, its components and its alerts",
            description = "A delete, not an auto-resolve: an asset's alerts cite component rows the "
                    + "asset owns, so removing the asset removes them. The response says how many went "
                    + "with it. (Correlation itself never deletes an alert — a match a re-scan no "
                    + "longer reproduces is auto-resolved. This is an explicit operator action, which "
                    + "is a different thing.)")
    @ApiResponse(responseCode = "404", description = "No asset with that id")
    @DeleteMapping("/{id}")
    public ResponseEntity<AssetDeletionSummary> delete(@PathVariable UUID id) {
        return assetService.delete(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** An unreadable report is the client's problem, and the message says exactly what was wrong. */
    @ExceptionHandler(UnsupportedScanFormatException.class)
    public ResponseEntity<ErrorResponse> onUnsupportedFormat(UnsupportedScanFormatException e) {
        log.warn("Rejected asset scan upload: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    private static Set<String> toSet(List<String> values) {
        if (values == null) {
            return null;
        }
        Set<String> distinct = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                distinct.add(value.trim());
            }
        }
        return distinct;
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        return b != null && !b.isBlank() ? b.trim() : null;
    }

}
