package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.criteria.Predicate;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.vex.AuthorVexStatementRequest;
import net.jdesive.secy.model.vex.AuthoredVexResponse;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.VexDocumentResponse;
import net.jdesive.secy.model.vex.VexPrecedenceSettingsRequest;
import net.jdesive.secy.model.vex.VexPrecedenceSettingsResponse;
import net.jdesive.secy.model.vex.VexReconcileResponse;
import net.jdesive.secy.model.vex.VexStatementResponse;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.service.vex.InvalidVexUploadException;
import net.jdesive.secy.service.vex.VexDocumentNotFoundException;
import net.jdesive.secy.service.vex.VexDocumentParser;
import net.jdesive.secy.service.vex.VexDocumentRejectedException;
import net.jdesive.secy.service.vex.VexDocumentTooLargeException;
import net.jdesive.secy.service.vex.VexIngestionService;
import net.jdesive.secy.service.vex.AuthoredVex;
import net.jdesive.secy.service.vex.VexAuthoringService;
import net.jdesive.secy.service.vex.VexResolutionService;
import net.jdesive.secy.service.vex.VexResolutionService.VexReconcileSummary;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * VEX document ingestion (M1f — see ROADMAP.md's "M1f — VEX ingestion") and statement browsing.
 *
 * <p>Mirrors {@code SBOMController}'s upload contract: format detection and full parsing run
 * synchronously, before anything is queued or persisted, so a document that can never succeed is a
 * plain {@code 400}/{@code 413} with nothing left behind. The actual persistence, supersession and
 * alert reconciliation run as a {@code VEX_UPLOAD} job — poll {@code GET /jobs/{id}}.
 *
 * <p>TODO(tenancy-hardening): every operation here reads/writes {@link Tenant#DEFAULT_TENANT_ID},
 * matching every other controller in this codebase today. No role gating on any endpoint here
 * either — M1k's {@code POST /vex/statements} (below) closes the VEX-authoring gap but adds no
 * enforcement; any authenticated user may call it.
 */
@Slf4j
@Tag(name = "VEX", description = "OpenVEX / CSAF 2.0 / CycloneDX VEX ingestion and statement browsing (M1f)")
@RestController
@RequestMapping("vex")
public class VexController {

    private final VexProperties vexProperties;
    private final VexDocumentParser vexDocumentParser;
    private final VexIngestionService vexIngestionService;
    private final VexResolutionService vexResolutionService;
    private final VexDocumentRepository vexDocumentRepository;
    private final VexStatementRepository vexStatementRepository;
    private final ProductRepository productRepository;
    private final JobService jobService;
    private final VexAuthoringService vexAuthoringService;

    public VexController(VexProperties vexProperties, VexDocumentParser vexDocumentParser,
                         VexIngestionService vexIngestionService, VexResolutionService vexResolutionService,
                         VexDocumentRepository vexDocumentRepository, VexStatementRepository vexStatementRepository,
                         ProductRepository productRepository, JobService jobService,
                         VexAuthoringService vexAuthoringService) {
        this.vexProperties = vexProperties;
        this.vexDocumentParser = vexDocumentParser;
        this.vexIngestionService = vexIngestionService;
        this.vexResolutionService = vexResolutionService;
        this.vexDocumentRepository = vexDocumentRepository;
        this.vexStatementRepository = vexStatementRepository;
        this.productRepository = productRepository;
        this.jobService = jobService;
        this.vexAuthoringService = vexAuthoringService;
    }

    /* ------------------------------------------------------------------ */
    /* M1k — authoring (security-engineer VEX authoring / dispute)        */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Author a TENANT-origin VEX statement directly (M1k)",
            description = "Closes the one genuinely missing security-engineer capability: there was no "
                    + "way to assert VEX without crafting a document file. Validates synchronously -- same "
                    + "contract as POST /vex -- then runs the EXISTING ingestion pipeline unchanged: a newer "
                    + "statement from the same author on the same target supersedes an older one under the "
                    + "existing author-supersession rule, and an opposing TENANT statement from someone else "
                    + "triggers the existing conflict flagging. Requires authentication (author is the caller).")
    @ApiResponse(responseCode = "202", description = "Statement validated; ingest queued")
    @ApiResponse(responseCode = "400", description = "Bad cveId/purl/status/justification combination, or Unassigned productId")
    @ApiResponse(responseCode = "401", description = "No authenticated principal")
    @ApiResponse(responseCode = "404", description = "Unknown productId")
    @PostMapping(value = "/statements", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthoredVexResponse> authorStatement(@RequestBody AuthorVexStatementRequest request,
                                                                Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        AuthoredVex authored = vexAuthoringService.author(request, principal.getName(), principal);
        return new ResponseEntity<>(new AuthoredVexResponse(authored.job(), authored.documentId()), HttpStatus.ACCEPTED);
    }

    /* ------------------------------------------------------------------ */
    /* Upload                                                              */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Upload an OpenVEX, CSAF 2.0 (subset), or CycloneDX VEX document; validates synchronously, then queues ingest as a background job",
            description = "Returns immediately with a QUEUED VEX_UPLOAD job; poll GET /jobs/{id} for progress. "
                    + "Size, format detection and parsing happen before the job is queued, so a document that "
                    + "can never succeed is still a synchronous 400/413 with nothing queued. `origin` is "
                    + "required (TENANT or VENDOR) -- no document format reliably says which one a document is. "
                    + "`productId` scopes the document (e.g. an embedded CycloneDX VEX whose affects[].ref bom-refs "
                    + "resolve against that document's own components); omit it for an unscoped document.")
    @ApiResponse(responseCode = "202", description = "Document validated; ingest queued")
    @ApiResponse(responseCode = "400", description = "Malformed document, missing/unknown origin, or a bad request parameter")
    @ApiResponse(responseCode = "404", description = "Unknown productId")
    @ApiResponse(responseCode = "413", description = "Document exceeds secy.vex.max-document-bytes")
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> upload(
            @Parameter(description = "Required: TENANT or VENDOR — who issued this document") @RequestParam(required = false) String origin,
            @Parameter(description = "Optional: scope the document to one product") @RequestParam(required = false) UUID productId,
            HttpServletRequest request,
            Principal principal) throws IOException {

        byte[] body = readBoundedBody(request);

        VexOrigin parsedOrigin = VexOrigin.fromApiValue(origin);

        if (productId != null) {
            Product product = productRepository.findById(productId).orElse(null);
            if (product == null) {
                return ResponseEntity.notFound().build();
            }
            if (product.isUnassigned()) {
                throw new InvalidVexUploadException("VEX cannot be scoped to the Unassigned bucket");
            }
        }

        ParsedVexDocument parsed = vexDocumentParser.parse(body);

        Job job = jobService.create(JobType.VEX_UPLOAD, principal);
        VexDocument placeholder = vexIngestionService.createPlaceholder(parsed, body, parsedOrigin, productId, job.getId());

        log.info("Queued {} VEX upload {} ({} origin) as job {}: {} statements pending ingest",
                parsed.format(), placeholder.getId(), parsedOrigin, job.getId(), parsed.statements().size());

        return new ResponseEntity<>(job, HttpStatus.ACCEPTED);
    }

    private byte[] readBoundedBody(HttpServletRequest request) throws IOException {
        long limit = vexProperties.getMaxDocumentBytes();
        long declared = request.getContentLengthLong();
        if (declared > limit) {
            throw new VexDocumentTooLargeException("VEX document exceeds the " + limit + "-byte limit");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        try (InputStream in = request.getInputStream()) {
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > limit) {
                    throw new VexDocumentTooLargeException("VEX document exceeds the " + limit + "-byte limit");
                }
                buffer.write(chunk, 0, read);
            }
        }
        return buffer.toByteArray();
    }

    /* ------------------------------------------------------------------ */
    /* Documents                                                           */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "List uploaded VEX documents, newest first")
    @GetMapping("/documents")
    public Page<VexDocumentResponse> documents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @Parameter(description = "Filter to active or inactive (superseded/deactivated) documents; omit for both")
            @RequestParam(required = false) Boolean active) {
        Pageable pageable = PageRequest.of(page, size);
        Page<VexDocument> result = active == null
                ? vexDocumentRepository.findAllByTenantIdOrderByUploadedAtDesc(Tenant.DEFAULT_TENANT_ID, pageable)
                : vexDocumentRepository.findAllByTenantIdAndActiveOrderByUploadedAtDesc(Tenant.DEFAULT_TENANT_ID, active, pageable);
        return result.map(VexDocumentResponse::from);
    }

    @Operation(summary = "One VEX document")
    @ApiResponse(responseCode = "404", description = "No document with that id")
    @GetMapping("/documents/{id}")
    public ResponseEntity<VexDocumentResponse> document(@PathVariable UUID id) {
        return vexDocumentRepository.findById(id)
                .map(d -> ResponseEntity.ok(VexDocumentResponse.from(d)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "The statements one VEX document parsed into, in document order")
    @ApiResponse(responseCode = "404", description = "No document with that id")
    @GetMapping("/documents/{id}/statements")
    public ResponseEntity<Page<VexStatementResponse>> documentStatements(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        if (vexDocumentRepository.findById(id).isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Page<VexStatement> result = vexStatementRepository.findAllByDocumentIdOrderByOrdinalAsc(id, PageRequest.of(page, size));
        return ResponseEntity.ok(result.map(VexStatementResponse::from));
    }

    @Operation(summary = "Deactivate a VEX document",
            description = "Flags the document and its statements inactive and re-resolves every alert they "
                    + "could have affected. Never deletes rows. Idempotent — deactivating an already-inactive "
                    + "document is a no-op that still returns 200.")
    @ApiResponse(responseCode = "404", description = "No document with that id")
    @PostMapping("/documents/{id}/deactivate")
    public ResponseEntity<VexDocumentResponse> deactivate(@PathVariable UUID id) {
        return ResponseEntity.ok(VexDocumentResponse.from(vexIngestionService.deactivate(id)));
    }

    /* ------------------------------------------------------------------ */
    /* Statements                                                          */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Browse VEX statements across every document, filtered")
    @GetMapping("/statements")
    public Page<VexStatementResponse> statements(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String cveId,
            @RequestParam(required = false) VexStatus status,
            @RequestParam(required = false) VexOrigin origin,
            @Parameter(description = "Defaults to true — only active statements") @RequestParam(defaultValue = "true") boolean active,
            @Parameter(description = "true: only statements with a resolvable matchKey; false: only unmatchable ones; omit for both")
            @RequestParam(required = false) Boolean matchable) {
        Specification<VexStatement> spec = statementSpecification(cveId, status, origin, active, matchable);
        Page<VexStatement> result = vexStatementRepository.findAll(spec, PageRequest.of(page, size));
        return result.map(VexStatementResponse::from);
    }

    private static Specification<VexStatement> statementSpecification(String cveId, VexStatus status, VexOrigin origin,
                                                                       boolean active, Boolean matchable) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("tenantId"), Tenant.DEFAULT_TENANT_ID));
            predicates.add(cb.equal(root.get("active"), active));
            if (cveId != null && !cveId.isBlank()) {
                predicates.add(cb.equal(cb.upper(root.get("cveId")), cveId.trim().toUpperCase(java.util.Locale.ROOT)));
            }
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (origin != null) {
                predicates.add(cb.equal(root.get("origin"), origin));
            }
            if (matchable != null) {
                predicates.add(matchable ? cb.isNotNull(root.get("matchKey")) : cb.isNull(root.get("matchKey")));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    /* ------------------------------------------------------------------ */
    /* Reconcile + settings                                                */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Re-resolve VEX for every alert with an active statement or a stale snapshot",
            description = "Self-heals the narrow race between a concurrent correlation and a VEX ingest/deactivation. "
                    + "Also runs automatically after every upload, deactivation and precedence change.")
    @PostMapping("/reconcile")
    public VexReconcileResponse reconcile() {
        VexReconcileSummary summary = vexResolutionService.reconcileAll(Tenant.DEFAULT_TENANT_ID);
        return new VexReconcileResponse(summary.alertsEvaluated(), summary.alertsChanged());
    }

    @Operation(summary = "The tenant's VEX precedence policy", description = "Default TENANT_OVER_VENDOR if never configured.")
    @GetMapping("/settings/precedence")
    public VexPrecedenceSettingsResponse getPrecedence() {
        return VexPrecedenceSettingsResponse.of(vexResolutionService.getPolicy(Tenant.DEFAULT_TENANT_ID));
    }

    @Operation(summary = "Set the tenant's VEX precedence policy",
            description = "Synchronously re-resolves every alert the change could affect before returning.")
    @ApiResponse(responseCode = "400", description = "Unknown policy value")
    @PutMapping("/settings/precedence")
    public VexPrecedenceSettingsResponse setPrecedence(@RequestBody VexPrecedenceSettingsRequest request) {
        VexPrecedencePolicy policy = VexPrecedencePolicy.fromApiValue(request.policy());
        VexReconcileSummary summary = vexResolutionService.setPolicy(Tenant.DEFAULT_TENANT_ID, policy);
        return new VexPrecedenceSettingsResponse(policy, summary.alertsEvaluated(), summary.alertsChanged());
    }

    /* ------------------------------------------------------------------ */
    /* Exception handlers                                                  */
    /* ------------------------------------------------------------------ */

    @ExceptionHandler({VexDocumentRejectedException.class, InvalidVexUploadException.class})
    public ResponseEntity<ErrorResponse> onBadRequest(RuntimeException e) {
        log.warn("Rejected VEX request: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    @ExceptionHandler(VexDocumentTooLargeException.class)
    public ResponseEntity<ErrorResponse> onTooLarge(VexDocumentTooLargeException e) {
        log.warn("Rejected VEX upload: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(new ErrorResponse(e.getMessage()));
    }

    @ExceptionHandler(VexDocumentNotFoundException.class)
    public ResponseEntity<ErrorResponse> onNotFound(VexDocumentNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(e.getMessage()));
    }

}
