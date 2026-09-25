package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.cbom.CryptoAssetDetailResponse;
import net.jdesive.secy.model.cbom.CryptoAssetFilter;
import net.jdesive.secy.model.cbom.CryptoAssetResponse;
import net.jdesive.secy.model.cbom.QuantumFindingFilter;
import net.jdesive.secy.model.cbom.QuantumFindingResponse;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.service.cbom.CbomQueryService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * CycloneDX 1.6 {@code cryptographic-asset} inventory and quantum-vulnerability findings (M1g,
 * ROADMAP.md — "M1g — CBOM ingestion").
 *
 * <p><b>No new upload endpoint.</b> CBOM data arrives as ordinary components (type
 * {@code cryptographic-asset}) inside a normal CycloneDX document — {@code POST /sbom},
 * {@code POST /sbom/{productId}/sboms} and the GitHub connector all pick it up automatically once the
 * normalizer extracts {@code cryptoProperties} (requires {@code specVersion >= 1.6}; see
 * {@code CycloneDxSpecVersion}). A <em>standalone</em> CBOM (every component crypto-typed) uses the
 * same endpoints and replaces the product's whole active SBOM for its slot, exactly like any other
 * upload — see ROADMAP.md's M1g decision D1 for that interaction and the recommended workarounds.
 *
 * <p><b>Not part of {@code GET /actionable}.</b> A quantum-vulnerability finding has no KEV/EPSS/CVSS
 * to rank it by — same reasoning as {@code LifecycleDriftController}.
 */
@Tag(name = "CBOM", description = "CycloneDX 1.6 cryptographic-asset inventory and quantum-vulnerability findings")
@RestController
@RequestMapping("/cbom")
@RequiredArgsConstructor
public class CbomController {

    private final CbomQueryService cbomQueryService;

    @Operation(summary = "List crypto assets, paged and filtered",
            description = "Spring `Page` shape. Defaults to `includeInactive=false` (only assets on "
                    + "an active SBOM). Sorted by component name asc, then id asc.")
    @GetMapping("/assets")
    public Page<CryptoAssetResponse> assets(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) UUID productId,
            @RequestParam(required = false) UUID sbomId,
            @RequestParam(required = false) CryptoAssetType assetType,
            @RequestParam(required = false) QuantumVulnerabilityStatus quantumStatus,
            @RequestParam(defaultValue = "false") boolean includeInactive) {
        CryptoAssetFilter filter =
                new CryptoAssetFilter(productId, sbomId, assetType, quantumStatus, includeInactive);
        return cbomQueryService.findAssets(page, size, filter);
    }

    @Operation(summary = "One crypto asset in full, including its sanitized cryptoProperties JSON")
    @ApiResponse(responseCode = "404", description = "No crypto asset with that id")
    @GetMapping("/assets/{id}")
    public ResponseEntity<CryptoAssetDetailResponse> assetDetail(@PathVariable UUID id) {
        return cbomQueryService.findAssetDetailFull(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "List quantum-vulnerability findings, paged and filtered",
            description = "Spring `Page` shape. Defaults to `lifecycleState=ACTIVE`. Sorted newest first.")
    @GetMapping("/quantum-findings")
    public Page<QuantumFindingResponse> quantumFindings(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) UUID productId,
            @RequestParam(required = false) CryptoAssetType assetType,
            @RequestParam(required = false) QuantumVulnerableFamily family,
            @Parameter(description = "Defaults to ACTIVE. AUTO_RESOLVED shows what a later reconcile "
                    + "stopped reproducing — kept as evidence, never deleted")
            @RequestParam(required = false) AlertLifecycleState lifecycleState) {
        QuantumFindingFilter filter = new QuantumFindingFilter(productId, assetType, family, lifecycleState);
        return cbomQueryService.findFindings(page, size, filter);
    }

    @Operation(summary = "One quantum-vulnerability finding in full")
    @ApiResponse(responseCode = "404", description = "No quantum-vulnerability finding with that id")
    @GetMapping("/quantum-findings/{id}")
    public ResponseEntity<QuantumFindingResponse> quantumFindingDetail(@PathVariable UUID id) {
        return cbomQueryService.findFindingDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
