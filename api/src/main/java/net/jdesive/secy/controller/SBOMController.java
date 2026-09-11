package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
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

    @Autowired
    public SBOMController(SBOMService sbomService, ProductService productService,
                          VulnerabilityAlertRepository alertRepository, SbomParser sbomParser) {
        this.sbomService = sbomService;
        this.productService = productService;
        this.alertRepository = alertRepository;
        this.sbomParser = sbomParser;
    }

    /**
     * Upload an SBOM.
     *
     * <p>The body is taken as a raw {@code JsonNode} rather than bound to a format-specific type,
     * because one endpoint has to serve two document shapes. {@link SbomParser} sniffs which one
     * arrived ({@code bomFormat} / {@code spdxVersion}) and parses it into the normalized model;
     * an unrecognised document is a {@code 400}, never a half-ingested SBOM.
     */
    @Operation(summary = "Upload a CycloneDX or SPDX (2.2/2.3 JSON) SBOM for a product, scan it, and make it the active one")
    @PostMapping(value = "/{productId}/sboms", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SBOM> uploadSbom(
            @PathVariable UUID productId,
            @RequestParam(value = "productVersion", defaultValue = "Unknown") String productVersion,
            @RequestBody JsonNode body) {

        // 1. Verify the product exists
        Product product = this.productService.getProductById(productId);

        // 2. Detect the format and normalize. Throws UnsupportedSbomFormatException -> 400.
        NormalizedSbom document = sbomParser.parse(body);

        // 3. Ingest, Scan, and set as Active (all handled in the service layer)
        SBOM savedSbom = sbomService.ingestAndPrepare(product, document, productVersion);

        log.info("Ingested {} SBOM {} for product {}: {} components",
                document.format().label(), savedSbom.getId(), productId, document.components().size());

        return new ResponseEntity<>(savedSbom, HttpStatus.CREATED);
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
