package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.finding.FindingFilter;
import net.jdesive.secy.model.finding.FindingResponse;
import net.jdesive.secy.model.finding.FindingTypeInfo;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.service.finding.FindingService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * The M1j {@code Finding} read-model surface — a typed union over five existing tables (plus a
 * {@code PROVENANCE} stub), parallel to {@code /actionable} and never touching it. See
 * {@code FindingService}'s Javadoc for the N-arm tiered paging this list endpoint runs.
 */
@Tag(name = "Findings",
        description = "M1j read-model union over vulnerability/compromise/lifecycle-drift/quantum-vulnerable/"
                + "sbom-quality findings, plus a PROVENANCE stub (M4)")
@RestController
@RequestMapping("/findings")
@RequiredArgsConstructor
public class FindingController {

    private final FindingService findingService;

    @Operation(
            summary = "List findings across all five finding tables, paged and filtered",
            description = """
                    Spring `Page` shape. Tiered like `/actionable` but with five arms instead of two: \
                    COMPROMISE, then VULNERABILITY (actionable only — same funnel population as \
                    `/actionable`), then LIFECYCLE_DRIFT, QUANTUM_VULNERABLE, SBOM_QUALITY (fixed \
                    order, not a ranking claim — those three are unscored).

                    Unlike `/actionable`, this shows NOT_AFFECTED and RESOLVED rows with their \
                    derived `status` — nothing is hidden by VEX or triage state, only by \
                    `lifecycleState` (`includeResolved=true` shows AUTO_RESOLVED rows too).""")
    @GetMapping
    public Page<FindingResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Restrict to one arm. PROVENANCE always returns an empty page.")
            @RequestParam(required = false) FindingType type,
            @Parameter(description = "Only findings scoped to this product.")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "Only findings scoped to this asset. Excludes LIFECYCLE_DRIFT/"
                    + "QUANTUM_VULNERABLE/SBOM_QUALITY entirely — they have no asset concept.")
            @RequestParam(required = false) UUID assetId,
            @Parameter(description = "Also include AUTO_RESOLVED rows. Default false.")
            @RequestParam(defaultValue = "false") boolean includeResolved,
            @Parameter(description = "true: only findings attached to an action item. false: only "
                    + "unattached ones. Omit for no restriction.")
            @RequestParam(required = false) Boolean linked) {

        FindingFilter filter = new FindingFilter(type, productId, assetId, includeResolved, linked);
        return findingService.list(page, size, filter);
    }

    @Operation(summary = "The M1j finding-type inventory", description = "Includes PROVENANCE with `available=false` — a pure M4 stub.")
    @GetMapping("/types")
    public List<FindingTypeInfo> types() {
        return findingService.types();
    }

    @Operation(summary = "One finding in full", description = "PROVENANCE always 404s — no backing table exists yet.")
    @GetMapping("/{type}/{id}")
    public ResponseEntity<FindingResponse> detail(@PathVariable FindingType type, @PathVariable UUID id) {
        return findingService.detail(type, id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
