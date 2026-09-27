package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.quality.SbomQualityFindingFilter;
import net.jdesive.secy.model.quality.SbomQualityFindingResponse;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.service.quality.SbomQualityQueryService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * SBOM NTIA minimum-elements quality findings (M1h, ROADMAP.md — "M1h — SBOM quality scoring") — a
 * (product, lifecycle-stage slot) — or bucket-SBOM — whose current active SBOM scores below the
 * NTIA completeness threshold.
 *
 * <p><b>No new upload endpoint.</b> Every SBOM ingested through the existing endpoints
 * (manual upload, GitHub connector) is scored inline; the per-document score itself rides along on
 * that SBOM in {@code GET /products}/{@code GET /products/{id}} (each {@code sboms[]} entry's
 * {@code quality} field) — this controller surfaces only the derived, per-slot low-quality finding.
 *
 * <p><b>Not part of {@code GET /actionable}.</b> A quality finding has no KEV/EPSS/CVSS to rank it
 * by, same reasoning as {@code LifecycleDriftController}/{@code CbomController}.
 */
@Tag(name = "SBOM quality",
        description = "NTIA minimum-elements completeness findings for a product's (or bucket SBOM's) current SBOM")
@RestController
@RequestMapping("/sbom-quality")
@RequiredArgsConstructor
public class SbomQualityController {

    private final SbomQualityQueryService sbomQualityQueryService;

    @Operation(
            summary = "List SBOM quality findings, paged and filtered",
            description = """
                    Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed).

                    Each SBOM is scored 0-100 against the NTIA minimum elements — supplier, component \
                    name, component version, unique identifier and dependency relationship (all \
                    per-component coverage), plus document-level author and timestamp — equal weight, \
                    floor-rounded. A finding is raised per (product, lifecycle-stage slot) — or per \
                    bucket SBOM for the Unassigned product — when the CURRENT active SBOM for that \
                    slot scores strictly below 70. Dependency relationship is checked for PRESENCE \
                    only (whether a component's bom-ref appears in any declared dependency edge) — \
                    this does not build or validate the dependency graph.

                    Defaults to `lifecycleState=ACTIVE`. Sorted newest first.""")
    @GetMapping
    public Page<SbomQualityFindingResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Only findings for this product")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "Only findings whose representative SBOM matches")
            @RequestParam(required = false) UUID sbomId,
            @Parameter(description = "SOURCE, BUILD, ANALYZED or DEPLOYED — omit for the unstaged slot")
            @RequestParam(required = false) SbomLifecycleStage lifecycleStage,
            @Parameter(description = "Defaults to ACTIVE. AUTO_RESOLVED shows what a later reconcile "
                    + "stopped reproducing — kept as evidence, never deleted")
            @RequestParam(required = false) AlertLifecycleState lifecycleState) {

        SbomQualityFindingFilter filter = new SbomQualityFindingFilter(productId, sbomId, lifecycleStage, lifecycleState);
        return sbomQualityQueryService.find(page, size, filter);
    }

    @Operation(summary = "One SBOM quality finding in full")
    @ApiResponse(responseCode = "404", description = "No SBOM quality finding with that id")
    @GetMapping("/{id}")
    public ResponseEntity<SbomQualityFindingResponse> detail(@PathVariable UUID id) {
        return sbomQualityQueryService.findDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
