package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.service.ActionableService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * The primary screen's endpoint: the short list of vulnerabilities that actually matter.
 *
 * <p>Protected like everything else — {@code SecurityConfig} authenticates every path outside
 * {@code /auth/**}, health and the OpenAPI docs, so no entry is needed there for this one.
 */
@Tag(name = "Actionable", description = "Vulnerabilities that cleared the funnel: KEV-listed or EPSS above the threshold")
@RestController
@RequestMapping("/actionable")
@RequiredArgsConstructor
public class ActionableController {

    private final ActionableService actionableService;

    @Operation(
            summary = "List actionable items, paged and filtered",
            description = "Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed). "
                    + "Only alerts with `actionable = true` are returned. Sorted by EPSS score "
                    + "descending with unscored CVEs last, then newest first — the sort is fixed. "
                    + "Only alerts whose lifecycle state is ACTIVE are returned; a match a re-scan no "
                    + "longer reproduces is auto-resolved and drops off this list without being deleted.")
    @GetMapping
    public Page<ActionableItemResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Only alerts on SBOMs belonging to this product")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "Accepted and ignored until the Asset model lands in Phase 4")
            @RequestParam(required = false) UUID assetId,
            @Parameter(description = "Exact funnel reason; KEV_AND_EPSS_HIGH is its own value")
            @RequestParam(required = false) ActionableReason reason,
            @Parameter(description = "CVSS base score at or above this; unscored CVEs are excluded")
            @RequestParam(required = false) Double minCvss,
            @Parameter(description = "Accepted and ignored until the Phase 7 triage state machine lands")
            @RequestParam(required = false) String state,
            @RequestParam(required = false) FixState fixState,
            @Parameter(description = "Exploit maturity at or above this (NONE < POC < WEAPONIZED < IN_THE_WILD)")
            @RequestParam(required = false) ExploitMaturity minExploitMaturity,
            @Parameter(description = "Exact correlation confidence: EXACT (an advisory named this version), "
                    + "RANGE (identified package, version inside a stated range) or HEURISTIC (name guess "
                    + "or unbounded CPE wildcard)")
            @RequestParam(required = false) MatchConfidence matchConfidence) {

        ActionableFilter filter = new ActionableFilter(
                productId, assetId, reason, minCvss, state, fixState, minExploitMaturity, matchConfidence);
        return actionableService.findActionable(page, size, filter);
    }

    @Operation(
            summary = "One actionable item in full",
            description = "The row plus the complete CVE, every component the same CVE affects, and "
                    + "the feed evidence behind the verdict (KEV entry, EPSS entry, CVE references).")
    @ApiResponse(responseCode = "404", description = "No alert with that id")
    @GetMapping("/{id}")
    public ResponseEntity<ActionableDetailResponse> detail(@PathVariable UUID id) {
        return actionableService.findDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
