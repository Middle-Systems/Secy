package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.scoring.RiskRollupResponse;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.scoring.RiskRollupService;
import net.jdesive.secy.service.scoring.ScoringWeights;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.UUID;

/**
 * M1i's scoring surface (ROADMAP.md — "Scoring engine rework"): per-scope rollups, the weights model
 * in force, and the rescore trigger. Per-finding scores/breakdowns live on the existing
 * {@code /actionable} endpoints instead — see {@code ActionableItemResponse.riskScore} and
 * {@code ActionableDetailResponse.riskScoreBreakdown}.
 */
@Tag(name = "Risk score", description = "M1i per-scope risk rollups, the active weights model, and the rescore job")
@RestController
@RequiredArgsConstructor
public class RiskScoreController {

    private final RiskRollupService riskRollupService;

    private final JobService jobService;

    @Operation(
            summary = "One product's risk rollup",
            description = "The maximum risk score among the product's default GET /actionable vulnerability "
                    + "population, which alert produced it, and how many findings are (un)scored. Compromise "
                    + "findings on the product are counted separately and never change the score.")
    @ApiResponse(responseCode = "404", description = "No product with that id")
    @GetMapping("/products/{id}/risk-score")
    public ResponseEntity<RiskRollupResponse> productRollup(@PathVariable UUID id) {
        return riskRollupService.forProduct(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "One asset's risk rollup",
            description = "The mirror image of GET /products/{id}/risk-score, scoped to what a scanner found "
                    + "on this asset. An asset linked to a product never leaks into that product's own rollup.")
    @ApiResponse(responseCode = "404", description = "No asset with that id")
    @GetMapping("/assets/{id}/risk-score")
    public ResponseEntity<RiskRollupResponse> assetRollup(@PathVariable UUID id) {
        return riskRollupService.forAsset(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "The weights model currently scoring every finding",
            description = "The full ScoringWeights record — model version and every ScoreInput's weight(s). "
                    + "Every tenant uses the same weights today (ScoringWeightsProvider.forTenant is a stub); "
                    + "per-tenant weights are a future expansion, not a M1i feature.")
    @GetMapping("/risk-score/model")
    public ScoringWeights model() {
        return ScoringWeights.DEFAULT;
    }

    // TODO(tenancy-hardening): restrict to an effective tenant admin (TenantAccessService
    // .requireTenantAdmin, which now exists per M1k) — today every authenticated user can trigger a
    // rescore, same as every other ingest endpoint.
    @Operation(
            summary = "Queue a full risk-score rescore",
            description = "Rescores every vulnerability_alert from its current CVSS/KEV/EPSS/exploit-maturity/"
                    + "fix/VEX snapshots and current lifecycle stage — no enrichment side effects. For backfill "
                    + "(pre-M1i rows are null until their next enrichment or this job) and future weights-model "
                    + "version bumps. A singleton job: a second call while one is in flight returns that job.")
    @ApiResponse(responseCode = "202", description = "Rescore queued (or already in flight)")
    @PostMapping("/risk-score/rescore")
    public ResponseEntity<?> rescore(Principal principal) {
        return ResponseEntity.accepted().body(jobService.enqueue(JobType.RISK_RESCORE, principal));
    }

}
