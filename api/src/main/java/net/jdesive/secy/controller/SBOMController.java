package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.SBOMService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@Slf4j
@Tag(name = "SBOM", description = "CycloneDX SBOM upload and the vulnerability alerts derived from it")
@RestController
@RequestMapping("sbom")
public class SBOMController {

    private SBOMService sbomService;
    private ProductService productService;
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    public SBOMController(SBOMService sbomService, ProductService productService, VulnerabilityAlertRepository alertRepository) {
        this.sbomService = sbomService;
        this.productService = productService;
        this.alertRepository = alertRepository;
    }

    @Operation(summary = "Upload a CycloneDX SBOM for a product, scan it, and make it the active one")
    @PostMapping("/{productId}/sboms")
    public ResponseEntity<SBOM> uploadSbom(
            @PathVariable UUID productId,
            @RequestParam(value = "productVersion", defaultValue = "Unknown") String productVersion,
            @RequestBody CycloneDXFile cycloneDXFile) {

        // 1. Verify the product exists
        Product product = this.productService.getProductById(productId);

        // 2. Ingest, Scan, and set as Active (all handled in the service layer)
        SBOM savedSbom = sbomService.ingestAndPrepare(product, cycloneDXFile, productVersion);

        log.info(savedSbom.toString());

        return new ResponseEntity<>(savedSbom, HttpStatus.CREATED);
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
