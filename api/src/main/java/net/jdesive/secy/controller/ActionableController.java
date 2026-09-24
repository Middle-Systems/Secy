package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.model.actionable.ActionableItemType;
import net.jdesive.secy.model.actionable.AddCommentRequest;
import net.jdesive.secy.model.actionable.BulkTriagePatchRequest;
import net.jdesive.secy.model.actionable.TriageEventResponse;
import net.jdesive.secy.model.actionable.TriagePatchRequest;
import net.jdesive.secy.model.actionable.TriageStatusResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.security.AppUserPrincipal;
import net.jdesive.secy.service.ActionableService;
import net.jdesive.secy.service.TriageService;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * The primary screen's endpoint: the short list of vulnerabilities that actually matter.
 *
 * <p>Protected like everything else — {@code SecurityConfig} authenticates every path outside
 * {@code /auth/**}, health and the OpenAPI docs, so no entry is needed there for this one.
 */
@Tag(name = "Actionable",
        description = "Everything that cleared the funnel: KEV-listed, EPSS above the threshold, "
                + "or a supply-chain compromise finding")
@RestController
@RequestMapping("/actionable")
@RequiredArgsConstructor
public class ActionableController {

    private final ActionableService actionableService;

    private final TriageService triageService;

    private final AppUserRepository userRepository;

    @Operation(
            summary = "List actionable items, paged and filtered",
            description = """
                    Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed).

                    **A typed union since Phase 6.** Every row carries `itemType`:

                    - `VULNERABILITY` — a `vulnerability_alert` with `actionable = true` (KEV-listed \
                    or EPSS above `secy.actionable.epss-threshold`). Detail at `GET /actionable/{id}`.
                    - `COMPROMISE` — a `compromise_finding`: a malicious package or a known-malware \
                    file hash. It has no CVE, so `cveId`, `cvssScore`, `epssScore`, `kevDueDate`, \
                    `exploitMaturity`, `fixState` and `matchConfidence` are null on these rows, and \
                    the `compromise*` / `ioc*` fields are populated instead. Detail at \
                    `GET /compromise/{id}` — **not** `/actionable/{id}`, which 404s for a \
                    compromise id.

                    **The sort is fixed**, in two tiers: every compromise finding first \
                    (confidence CONFIRMED > LIKELY > INVESTIGATE, then freshest IOC), then every \
                    vulnerability alert by EPSS descending with unscored CVEs last, then newest \
                    first. A compromise finding outranks every CVE because it says malicious code is \
                    already in the build, not that something might be exploited.

                    Only rows whose lifecycle state is ACTIVE are returned, for both arms; a match a \
                    re-scan no longer reproduces is auto-resolved and drops off this list without \
                    being deleted.

                    A filter that only one arm can satisfy excludes the other arm entirely — \
                    `minCvss`, `fixState`, `minExploitMaturity` and `matchConfidence` return no \
                    compromise rows, and `confidence` returns no vulnerability rows.""")
    @GetMapping
    public Page<ActionableItemResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Only items on SBOMs belonging to this product. Applies to both arms.")
            @RequestParam(required = false) UUID productId,
            @Parameter(description = "Only items a scanner raised against this asset's components. "
                    + "Applies to both arms. Real from Phase 4 on — it was documented as "
                    + "accepted-and-ignored in Phases 1-2, so an unknown id now returns an empty page "
                    + "instead of the unfiltered list.")
            @RequestParam(required = false) UUID assetId,
            @Parameter(description = "Exact funnel reason; KEV_AND_EPSS_HIGH is its own value. "
                    + "COMPROMISE selects only compromise findings and is equivalent to itemType=COMPROMISE.")
            @RequestParam(required = false) ActionableReason reason,
            @Parameter(description = "CVSS base score at or above this; unscored CVEs are excluded. "
                    + "Excludes every compromise row, which has no CVSS score.")
            @RequestParam(required = false) Double minCvss,
            @Parameter(description = "Exact Phase 7 triage state (OPEN/ACKNOWLEDGED/SNOOZED/RESOLVED/"
                    + "FALSE_POSITIVE), for both arms. Omit for the default: RESOLVED, FALSE_POSITIVE "
                    + "and not-yet-expired SNOOZED rows are hidden; an expired snooze reappears on its own.")
            @RequestParam(required = false) String state,
            @Parameter(description = "Exact fix state. Excludes every compromise row — malware is removed, not fixed.")
            @RequestParam(required = false) FixState fixState,
            @Parameter(description = "Exploit maturity at or above this (NONE < POC < WEAPONIZED < IN_THE_WILD). "
                    + "Anything above NONE excludes every compromise row.")
            @RequestParam(required = false) ExploitMaturity minExploitMaturity,
            @Parameter(description = "Exact correlation confidence: EXACT (an advisory named this version), "
                    + "RANGE (identified package, version inside a stated range) or HEURISTIC (name guess "
                    + "or unbounded CPE wildcard). Excludes every compromise row.")
            @RequestParam(required = false) MatchConfidence matchConfidence,
            @Parameter(description = "Which arm of the union to return. Omit for both — the primary screen's default.")
            @RequestParam(required = false) ActionableItemType itemType,
            @Parameter(description = "Exact compromise confidence: CONFIRMED (the feed named this exact "
                    + "artefact), LIKELY (the match needed an inference) or INVESTIGATE (the IOC has gone "
                    + "stale). Excludes every vulnerability row.")
            @RequestParam(required = false) CompromiseConfidence confidence) {

        ActionableFilter filter = new ActionableFilter(
                productId, assetId, reason, minCvss, state, fixState, minExploitMaturity, matchConfidence,
                itemType, confidence);
        return actionableService.findActionable(page, size, filter);
    }

    @Operation(
            summary = "One actionable VULNERABILITY item in full",
            description = "The row plus the complete CVE, every component the same CVE affects, and "
                    + "the feed evidence behind the verdict (KEV entry, EPSS entry, CVE references).\n\n"
                    + "**Vulnerability rows only.** A compromise finding has no CVE, no KEV entry and no "
                    + "EPSS score, so it is fetched from `GET /compromise/{id}` instead; passing a "
                    + "compromise id here returns 404 rather than a mostly-null body. The list row's "
                    + "`itemType` says which endpoint to call.")
    @ApiResponse(responseCode = "404", description = "No alert with that id (including: it is a compromise finding)")
    @GetMapping("/{id}")
    public ResponseEntity<ActionableDetailResponse> detail(@PathVariable UUID id) {
        return actionableService.findDetail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /* ------------------------------------------------------------------ */
    /* Phase 7 — triage                                                   */
    /* ------------------------------------------------------------------ */

    @Operation(
            summary = "Update the triage state, assignee and/or snooze of one actionable item",
            description = """
                    Resolves against EITHER table — a `VulnerabilityAlert` id or a `CompromiseFinding` \
                    id — unlike `GET /actionable/{id}`, which is vulnerability-only. Triage is a \
                    cross-cutting concern over the whole union; the CVE-detail hop is not.

                    A PATCH, not a PUT: every field is optional, and a null one is left untouched. \
                    Every call appends one entry to the item's triage history, whether or not the \
                    state actually moved.""")
    @ApiResponse(responseCode = "404", description = "No vulnerability alert or compromise finding with that id")
    @PatchMapping("/{id}")
    public ResponseEntity<TriageStatusResponse> patchTriage(@PathVariable UUID id,
                                                              @RequestBody TriagePatchRequest request,
                                                              @AuthenticationPrincipal AppUserPrincipal principal) {
        User actingUser = actingUser(principal);
        return triageService.updateState(id, request.state(), request.assigneeId(), request.snoozedUntil(),
                        request.comment(), actingUser)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Add a free-text triage comment to one actionable item",
            description = "A history entry with no state change — `fromState`/`toState` are both null "
                    + "on the resulting event. Resolves against either table, like `PATCH /actionable/{id}`.")
    @ApiResponse(responseCode = "201", description = "Comment recorded")
    @ApiResponse(responseCode = "404", description = "No vulnerability alert or compromise finding with that id")
    @PostMapping("/{id}/comments")
    public ResponseEntity<TriageEventResponse> addComment(@PathVariable UUID id,
                                                            @Valid @RequestBody AddCommentRequest request,
                                                            @AuthenticationPrincipal AppUserPrincipal principal) {
        User actingUser = actingUser(principal);
        return triageService.addComment(id, request.comment(), actingUser)
                .map(event -> ResponseEntity.status(HttpStatus.CREATED).body(event))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Update the triage state and/or assignee of several actionable items at once",
            description = "Ids of either kind, mixed freely. An id that resolves to neither table is "
                    + "silently skipped rather than failing the whole batch — the same per-item "
                    + "tolerance a GitHub connector sync applies per-repo.")
    @PatchMapping
    public ResponseEntity<Map<String, Integer>> bulkPatchTriage(@RequestBody BulkTriagePatchRequest request,
                                                                  @AuthenticationPrincipal AppUserPrincipal principal) {
        User actingUser = actingUser(principal);
        int updated = triageService.bulkUpdateState(request.ids(), request.state(), request.assigneeId(), actingUser);
        return ResponseEntity.ok(Map.of("updated", updated));
    }

    @Operation(
            summary = "One actionable item's triage history, oldest first",
            description = "State transitions and standalone comments interleaved in one chronological "
                    + "timeline. Resolves against either table, like `PATCH /actionable/{id}`.")
    @ApiResponse(responseCode = "404", description = "No vulnerability alert or compromise finding with that id")
    @GetMapping("/{id}/history")
    public ResponseEntity<List<TriageEventResponse>> history(@PathVariable UUID id) {
        return triageService.history(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** The authenticated account behind the JWT, as the {@link User} entity {@code TriageService} attributes events to. */
    private User actingUser(AppUserPrincipal principal) {
        return userRepository.findById(principal.getId())
                .orElseThrow(() -> new NoSuchElementException("Authenticated user not found: " + principal.getId()));
    }

}
