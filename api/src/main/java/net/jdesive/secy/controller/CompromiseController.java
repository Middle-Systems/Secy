package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.compromise.CompromiseFilter;
import net.jdesive.secy.model.compromise.CompromiseFindingResponse;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.service.CompromiseService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Supply-chain compromise findings, browsable on their own.
 *
 * <p>Findings also appear inline in {@code GET /actionable} — that is the primary screen and where
 * an operator meets them first. This endpoint exists for the two things the union cannot do:
 * filtering on dimensions only a finding has ({@code type}, {@code confidence}), and looking at
 * {@code AUTO_RESOLVED} history, which {@code /actionable} hides by design.
 */
@Tag(name = "Compromise",
        description = "Supply-chain compromise findings: malicious packages and known-malware hashes")
@RestController
@RequestMapping("/compromise")
@RequiredArgsConstructor
public class CompromiseController {

    private final CompromiseService compromiseService;

    @Operation(
            summary = "List compromise findings, paged and filtered",
            description = """
                    Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed).

                    **The sort is fixed**: confidence (CONFIRMED, then LIKELY, then INVESTIGATE), \
                    then freshest IOC first, then newest. Severity is not part of the sort because \
                    every finding is CRITICAL by construction.

                    Defaults to `lifecycleState=ACTIVE`. Findings a re-scan stopped reproducing are \
                    never deleted — pass `lifecycleState=AUTO_RESOLVED` to see them.""")
    @GetMapping
    public Page<CompromiseFindingResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "MALICIOUS_PACKAGE (an OpenSSF MAL- record) or MALWARE_HASH "
                    + "(a MalwareBazaar SHA-256)")
            @RequestParam(required = false) CompromiseType type,
            @Parameter(description = "CONFIRMED (the feed named this exact artefact), LIKELY (the match "
                    + "needed an inference) or INVESTIGATE (the IOC has decayed past "
                    + "secy.compromise.ioc-stale-after)")
            @RequestParam(required = false) CompromiseConfidence confidence,
            @Parameter(description = "Only findings on SBOMs belonging to this product")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "Only findings on this asset's components")
            @RequestParam(required = false) UUID assetId,
            @Parameter(description = "A single component, of either kind — matched against both the "
                    + "sbom_component and asset_component references, so a caller holding a componentId "
                    + "from an /actionable row need not know which kind it is")
            @RequestParam(required = false) UUID componentId,
            @Parameter(description = "Defaults to ACTIVE. AUTO_RESOLVED shows what a re-scan stopped "
                    + "reproducing — kept as evidence, never deleted")
            @RequestParam(required = false) AlertLifecycleState lifecycleState) {

        CompromiseFilter filter =
                new CompromiseFilter(type, confidence, productId, assetId, componentId, lifecycleState);
        return compromiseService.find(page, size, filter);
    }

    @Operation(
            summary = "One compromise finding in full",
            description = "Same shape as a list row — a finding's full detail is its feed write-up and "
                    + "provenance, which the row already carries. This is the endpoint an `/actionable` "
                    + "row with `itemType = COMPROMISE` links its detail drawer to.")
    @ApiResponse(responseCode = "404", description = "No compromise finding with that id")
    @GetMapping("/{id}")
    public ResponseEntity<CompromiseFindingResponse> detail(@PathVariable UUID id) {
        return compromiseService.findDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
