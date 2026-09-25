package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.component.ComponentIdentityResponse;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.InvalidLifecycleStageException;
import net.jdesive.secy.service.InvalidProductTagException;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.ProductTaggingService;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.ComponentIdentityService;
import net.jdesive.secy.service.sbom.ComponentNotFoundException;
import net.jdesive.secy.service.sbom.SbomParser;
import net.jdesive.secy.service.sbom.UnsupportedSbomFormatException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Tag(name = "SBOM", description = "CycloneDX / SPDX SBOM upload and the vulnerability alerts derived from it")
@RestController
@RequestMapping("sbom")
public class SBOMController {

    private SBOMService sbomService;
    private ProductService productService;
    private ProductTaggingService productTaggingService;
    private VulnerabilityAlertRepository alertRepository;
    private SbomParser sbomParser;
    private JobService jobService;
    private ComponentIdentityService componentIdentityService;

    @Autowired
    public SBOMController(SBOMService sbomService, ProductService productService,
                          ProductTaggingService productTaggingService,
                          VulnerabilityAlertRepository alertRepository, SbomParser sbomParser,
                          JobService jobService, ComponentIdentityService componentIdentityService) {
        this.sbomService = sbomService;
        this.productService = productService;
        this.productTaggingService = productTaggingService;
        this.alertRepository = alertRepository;
        this.sbomParser = sbomParser;
        this.jobService = jobService;
        this.componentIdentityService = componentIdentityService;
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
                    + "document is still a synchronous 400 with nothing queued. The optional `stage` param "
                    + "(SOURCE/BUILD/ANALYZED/DEPLOYED, case-insensitive) records this SBOM's place in the "
                    + "SDLC (M1e); it wins over any stage the document itself declares (CycloneDX "
                    + "metadata.lifecycles), and an unrecognised value is a synchronous 400 with nothing "
                    + "queued. A staged upload does not deactivate other stages' active SBOMs for this "
                    + "product — see GET /products.")
    @ApiResponse(responseCode = "202", description = "Document validated; ingest queued")
    @PostMapping(value = "/{productId}/sboms", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> uploadSbom(
            @PathVariable UUID productId,
            @RequestParam(value = "productVersion", defaultValue = "Unknown") String productVersion,
            @RequestParam(value = "stage", required = false) String stage,
            @RequestBody JsonNode body,
            Principal principal) {

        // 1. Verify the product exists
        Product product = this.productService.getProductById(productId);

        // 2. Detect the format and normalize. Throws UnsupportedSbomFormatException -> 400. This is
        //    the only synchronous work: a document that can never succeed must never be queued.
        NormalizedSbom document = sbomParser.parse(body);

        // 2b. Parse the lifecycle stage param (M1e) -> 400 via onInvalidLifecycleStage for an
        //     unrecognised value, before anything is queued or written.
        SbomLifecycleStage explicitStage = SbomLifecycleStage.fromApiValue(stage);

        // 3. Queue the job, then persist a placeholder SBOM row pointing at it. The job carries no
        //    payload of its own (every other job type is a stateless feed pull), so the raw body and
        //    the job id live on the SBOM row instead — see SBOMService.ingestUploadJob.
        Job job = jobService.create(JobType.SBOM_UPLOAD, principal);
        SBOM placeholder = sbomService.createPlaceholder(product, document, productVersion, body.toString(),
                job.getId(), SbomIngestionSource.MANUAL_UPLOAD, null, explicitStage);

        log.info("Queued {} SBOM upload {} for product {} as job {}: {} components pending ingest",
                document.format().label(), placeholder.getId(), productId, job.getId(), document.components().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    /**
     * Upload an SBOM without naming a product — M1a's tag-driven path.
     *
     * <p>The document is resolved to a product by {@link ProductTaggingService#resolveProduct},
     * keyed on whatever {@code tag=key=value} params the caller supplied (repeatable; a value may
     * itself contain {@code '='} since only the first {@code '='} splits key from value). A tag
     * naming the tenant's configured key (default {@code secy:product}) lands the upload on the
     * product answering to that value, creating it if needed; no tags, no matching key, a blank
     * value, or the reserved value {@code "unassigned"} all land it in the tenant's Unassigned
     * bucket instead.
     *
     * <p>Everything is validated — tag params, then the document itself — before any write, exactly
     * like {@link #uploadSbom}: a request that can never succeed must never queue a job or create a
     * product.
     *
     * <p>The existing {@code POST /sbom/{productId}/sboms} manual-assignment path is unchanged and
     * stays available.
     */
    @Operation(summary = "Upload a CycloneDX or SPDX SBOM, resolving its product from tag params rather than a URL path",
            description = "Same synchronous-validate/async-ingest contract as POST /sbom/{productId}/sboms, but the "
                    + "product is resolved from repeated tag=key=value params via the tenant's configured product "
                    + "tag key (default secy:product); untagged or unresolved uploads land in the Unassigned bucket. "
                    + "The optional `stage` param (SOURCE/BUILD/ANALYZED/DEPLOYED, case-insensitive) works exactly "
                    + "as on the manual-assignment endpoint.")
    @ApiResponse(responseCode = "202", description = "Document validated; ingest queued")
    @PostMapping(value = "", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Job> uploadTaggedSbom(
            @RequestParam(value = "productVersion", defaultValue = "Unknown") String productVersion,
            @RequestParam(value = "tag", required = false) List<String> tags,
            @RequestParam(value = "stage", required = false) String stage,
            @RequestBody JsonNode body,
            Principal principal) {

        // 1. Parse the tag params. Malformed input (duplicate key, missing '=') -> 400 via
        //    onInvalidProductTag, before anything else runs.
        Map<String, String> tagMap = ProductTaggingService.parseTagParams(tags);

        // 2. Detect the format and normalize -> 400 via onUnsupportedFormat for a document that can
        //    never succeed. Same synchronous validation as the manual-assignment endpoint.
        NormalizedSbom document = sbomParser.parse(body);

        // 2b. Parse the lifecycle stage param (M1e) -> 400 via onInvalidLifecycleStage, before any
        //     product is resolved or created.
        SbomLifecycleStage explicitStage = SbomLifecycleStage.fromApiValue(stage);

        // 3. Resolve the product from the tags. TODO(tenancy-hardening): request-scoped tenant.
        Product product = productTaggingService.resolveProduct(Tenant.DEFAULT_TENANT_ID, tagMap);

        // 4-5. Queue the job, then persist the placeholder row against the resolved product.
        Job job = jobService.create(JobType.SBOM_UPLOAD, principal);
        SBOM placeholder = sbomService.createPlaceholder(product, document, productVersion, body.toString(),
                job.getId(), SbomIngestionSource.TAGGED_UPLOAD, null, explicitStage);

        log.info("Queued {} SBOM upload {} for tag-resolved product {} ({}) as job {}: {} components pending ingest",
                document.format().label(), placeholder.getId(), product.getId(), product.getName(), job.getId(),
                document.components().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    /** An unreadable document is the client's problem, and the message says exactly what was wrong. */
    @ExceptionHandler(UnsupportedSbomFormatException.class)
    public ResponseEntity<ErrorResponse> onUnsupportedFormat(UnsupportedSbomFormatException e) {
        log.warn("Rejected SBOM upload: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    /** A malformed {@code tag=key=value} param is the client's problem, same treatment as a bad document. */
    @ExceptionHandler(InvalidProductTagException.class)
    public ResponseEntity<ErrorResponse> onInvalidProductTag(InvalidProductTagException e) {
        log.warn("Rejected SBOM upload: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    /** An unrecognised {@code ?stage=} value (M1e) — a request that can never succeed must never queue a job. */
    @ExceptionHandler(InvalidLifecycleStageException.class)
    public ResponseEntity<ErrorResponse> onInvalidLifecycleStage(InvalidLifecycleStageException e) {
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

    /**
     * M1c's identity detail endpoint — the read path for the {@code @JsonIgnore}d
     * {@code identifiers}/{@code identityConflicts} collections on {@code SBOMComponent}.
     *
     * <p>TODO(tenancy-hardening): not tenant-filtered, matching every other endpoint here today.
     */
    @Operation(summary = "The declared CPE/SWID identifiers, content hashes, detected identity conflicts and provenance for one SBOM component")
    @GetMapping("/{sbomId}/components/{componentId}/identity")
    public ResponseEntity<ComponentIdentityResponse> getComponentIdentity(
            @PathVariable UUID sbomId, @PathVariable UUID componentId) {
        return ResponseEntity.ok(componentIdentityService.describe(sbomId, componentId));
    }

    /** No component with that id under that SBOM. */
    @ExceptionHandler(ComponentNotFoundException.class)
    public ResponseEntity<ErrorResponse> onComponentNotFound(ComponentNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(e.getMessage()));
    }

}
