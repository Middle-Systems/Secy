package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.lifecycle.LifecycleDriftFilter;
import net.jdesive.secy.model.lifecycle.LifecycleDriftFindingResponse;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import net.jdesive.secy.service.lifecycle.LifecycleDriftQueryService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * SBOM lifecycle-stage drift findings (M1e, ROADMAP.md — "SBOM lifecycle stages + diffing") —
 * disagreements between adjacent pairs of a product's Source/Build/Analyzed/Deployed SBOMs.
 *
 * <p>Three pairs are compared, each in one direction (downstream against upstream):
 * {@code SOURCE_BUILD}, {@code BUILD_DEPLOYED}, {@code BUILD_ANALYZED}. Source↔Deployed and
 * Source↔Analyzed are deliberately not compared — Build is the pivot every downstream artefact is
 * checked against. A finding is raised when the downstream (observed) SBOM has a component the
 * upstream (baseline) SBOM never declared ({@code UNEXPECTED_COMPONENT}), or declares a concrete
 * version the upstream SBOM never declared ({@code VERSION_MISMATCH}). A component present upstream
 * but missing downstream is computed but <b>never</b> raised as a finding — too noisy in practice
 * (partial runtime scanners, static linking, generators that only declare direct dependencies).
 *
 * <p><b>Not part of {@code GET /actionable}.</b> That endpoint ranks by KEV/EPSS/CVSS, none of which a
 * drift finding has — folding it in would either force a fake score or special-case the ranking. These
 * are their own endpoints until a later milestone gives drift a scoring model.
 */
@Tag(name = "Lifecycle drift",
        description = "Disagreements between adjacent Source/Build/Analyzed/Deployed SBOM stages of a product")
@RestController
@RequestMapping("/lifecycle-drift")
@RequiredArgsConstructor
public class LifecycleDriftController {

    private final LifecycleDriftQueryService lifecycleDriftQueryService;

    @Operation(
            summary = "List lifecycle drift findings, paged and filtered",
            description = """
                    Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed).

                    Compares three adjacent stage pairs — SOURCE_BUILD, BUILD_DEPLOYED, BUILD_ANALYZED \
                    (never SOURCE_DEPLOYED or SOURCE_ANALYZED) — and raises UNEXPECTED_COMPONENT or \
                    VERSION_MISMATCH findings when the downstream SBOM has something the upstream SBOM \
                    never vouched for. A component present upstream but missing downstream is computed \
                    but never raised.

                    Defaults to `lifecycleState=ACTIVE`. Sorted newest first.""")
    @GetMapping
    public Page<LifecycleDriftFindingResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Only findings for this product")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "SOURCE_BUILD, BUILD_DEPLOYED or BUILD_ANALYZED")
            @RequestParam(required = false) LifecycleStagePair stagePair,
            @Parameter(description = "UNEXPECTED_COMPONENT or VERSION_MISMATCH")
            @RequestParam(required = false) LifecycleDriftKind driftKind,
            @Parameter(description = "Defaults to ACTIVE. AUTO_RESOLVED shows what a later diff stopped "
                    + "reproducing — kept as evidence, never deleted")
            @RequestParam(required = false) AlertLifecycleState lifecycleState) {

        LifecycleDriftFilter filter = new LifecycleDriftFilter(productId, stagePair, driftKind, lifecycleState);
        return lifecycleDriftQueryService.find(page, size, filter);
    }

    @Operation(summary = "One lifecycle drift finding in full")
    @ApiResponse(responseCode = "404", description = "No lifecycle drift finding with that id")
    @GetMapping("/{id}")
    public ResponseEntity<LifecycleDriftFindingResponse> detail(@PathVariable UUID id) {
        return lifecycleDriftQueryService.findDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
