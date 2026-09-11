package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import net.jdesive.secy.service.sbom.UnsupportedSbomFormatException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.UUID;

@Slf4j
@Tag(name = "SBOM", description = "CycloneDX / SPDX SBOM upload and the vulnerability alerts derived from it")
@RestController
@RequestMapping("sbom")
public class SBOMController {

    private SBOMService sbomService;
    private ProductService productService;
    private VulnerabilityAlertRepository alertRepository;
    private SbomParser sbomParser;
    private JobService jobService;

    @Autowired
    public SBOMController(SBOMService sbomService, ProductService productService,
                          VulnerabilityAlertRepository alertRepository, SbomParser sbomParser,
                          JobService jobService) {
        this.sbomService = sbomService;
        this.productService = productService;
        this.alertRepository = alertRepository;
        this.sbomParser = sbomParser;
        this.jobService = jobService;
    }

    /**
     * Upload an SBOM.
     *
     * <p>The body is taken as a raw {@code JsonNode} rather than bound to a format-specific type,
     * because one endpoint has to serve two document shapes. {@link SbomParser} sniffs which one
     * arrived ({@code bomFormat} / {@code spdxVersion}) and parses it into the normalized model;
     * an unrecognised document is a {@code 400}, never a half-ingested SBOM. That detection/parsing
     * step stays synchronous — a client should never get a {@code 202} for a document that can never
     * succeed.
     *
     * <p><b>Breaking change (Phase 3):</b> this used to ingest, scan and answer {@code 201} with the
     * full {@link SBOM} synchronously. It now answers {@code 202} with a {@link Job} to poll —
     * persisting components, correlating alerts and scanning all move onto the {@code SBOM_UPLOAD}
     * job queue, consistent with the feed ingests. A placeholder {@code SBOM} row is created here (so
     * the response and any immediate {@code GET /products} carry a real id and a {@code QUEUED}
     * status) but its components are not populated until the job runs — poll
     * {@code GET /jobs/{id}} for progress/failure, and {@code GET /products} /
     * {@code GET /sbom/{sbomId}/vulnerabilities} for the result once it lands.
     */
    @Operation(summary = "Upload a CycloneDX or SPDX (2.2/2.3 JSON) SBOM for a product; validates synchronously, then queues ingest + scan as a background job",
            description = "Returns immediately with a QUEUED SBOM_UPLOAD job; poll GET /jobs/{id} for progress. "
                    + "Format detection and parsing happen before the job is queued, so an unrecognised "
                    + "document is still a synchronous 400 with nothing queued.")
    @ApiResponse(responseCode = "202", description = "Document validated; ingest queued")
    @PostMapping(value = "/{productId}/sboms", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> uploadSbom(
            @PathVariable UUID productId,
            @RequestParam(value = "productVersion", defaultValue = "Unknown") String productVersion,
            @RequestBody JsonNode body,
            Principal principal) {

        // 1. Verify the product exists
        Product product = this.productService.getProductById(productId);

        // 2. Detect the format and normalize. Throws UnsupportedSbomFormatException -> 400. This is
        //    the only synchronous work: a document that can never succeed must never be queued.
        NormalizedSbom document = sbomParser.parse(body);

        // 3. Queue the job, then persist a placeholder SBOM row pointing at it. The job carries no
        //    payload of its own (every other job type is a stateless feed pull), so the raw body and
        //    the job id live on the SBOM row instead — see SBOMService.ingestUploadJob.
        Job job = jobService.create(JobType.SBOM_UPLOAD, principal);
        SBOM placeholder = sbomService.createPlaceholder(product, document, productVersion, body.toString(), job.getId());

        log.info("Queued {} SBOM upload {} for product {} as job {}: {} components pending ingest",
                document.format().label(), placeholder.getId(), productId, job.getId(), document.components().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    /** An unreadable document is the client's problem, and the message says exactly what was wrong. */
    @ExceptionHandler(UnsupportedSbomFormatException.class)
    public ResponseEntity<ErrorResponse> onUnsupportedFormat(UnsupportedSbomFormatException e) {
        log.warn("Rejected SBOM upload: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    @Operation(summary = "List the vulnerability alerts raised against an SBOM's components")
    @GetMapping("/{sbomId}/vulnerabilities")
    public ResponseEntity<List<VulnerabilityAlert>> getSbomVulnerabilities(@PathVariable UUID sbomId) {
        // Using the high-performance query we built earlier
        List<VulnerabilityAlert> alerts = alertRepository.findAllBySbomIdWithIntelligence(sbomId);

        if (alerts.isEmpty()) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok(alerts);
    }

}
