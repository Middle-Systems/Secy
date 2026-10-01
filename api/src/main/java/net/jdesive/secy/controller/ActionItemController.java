package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.model.actionable.AddCommentRequest;
import net.jdesive.secy.model.actionitem.ActionItemDetailResponse;
import net.jdesive.secy.model.actionitem.ActionItemEventResponse;
import net.jdesive.secy.model.actionitem.ActionItemPatchRequest;
import net.jdesive.secy.model.actionitem.ActionItemResponse;
import net.jdesive.secy.model.actionitem.AttachFindingsRequest;
import net.jdesive.secy.model.actionitem.CreateActionItemRequest;
import net.jdesive.secy.model.actionitem.DisputeFindingRequest;
import net.jdesive.secy.model.actionitem.DisputeResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.security.AppUserPrincipal;
import net.jdesive.secy.service.access.OwnedByResolver;
import net.jdesive.secy.service.actionitem.ActionItemDisputeService;
import net.jdesive.secy.service.actionitem.ActionItemService;
import net.jdesive.secy.service.actionitem.InvalidActionItemException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

/**
 * The M1j {@code ActionItem} surface — the concrete remediation task over one or more findings, and
 * its status machine. Parallel to {@code /findings} and {@code /actionable}; neither is touched here.
 * No role gating on any endpoint here — M1k added the {@code ownedBy} view-level filter below, not
 * enforcement; {@code GET /action-items} with no {@code ownedBy} is unrestricted until Tenancy
 * hardening.
 */
@Slf4j
@Tag(name = "Action items",
        description = "M1j remediation tasks: manual creation over findings, status machine (open/in "
                + "progress/risk accepted/resolved, plus derived not-affected/auto-reopen), assignment, comments")
@RestController
@RequestMapping("/action-items")
@RequiredArgsConstructor
public class ActionItemController {

    private final ActionItemService actionItemService;
    private final ActionItemDisputeService actionItemDisputeService;
    private final AppUserRepository userRepository;
    private final OwnedByResolver ownedByResolver;

    @Operation(
            summary = "Create an action item over one or more findings",
            description = """
                    The scope (exactly one product OR asset) is derived from the attached findings, \
                    never client-supplied — every finding must share it, or 400. Manual grouping \
                    only; nothing auto-creates an action item.""")
    @PostMapping
    public ResponseEntity<ActionItemDetailResponse> create(@Valid @RequestBody CreateActionItemRequest request,
                                                             @AuthenticationPrincipal AppUserPrincipal principal) {
        ActionItemDetailResponse response = actionItemService.create(request, actingUser(principal));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @Operation(
            summary = "List action items, paged and filtered",
            description = "`status` matches the EFFECTIVE status. Omitted, the default hides effective "
                    + "RESOLVED/NOT_AFFECTED/RISK_ACCEPTED — an expired acceptance or a reopen already "
                    + "reads as OPEN, so it stays visible. Sorted: effective OPEN, then IN_PROGRESS, "
                    + "then the rest, then score desc (nulls last), then updatedAt desc, then id. "
                    + "`ownedBy` (M1k) is `me` or a user UUID — restricts to items scoped to a product "
                    + "that user owns (asset-scoped items are always excluded by it); omit for no "
                    + "restriction, which is this endpoint's only behavior until Tenancy hardening.")
    @GetMapping
    public Page<ActionItemResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) UUID productId,
            @RequestParam(required = false) UUID assetId,
            @RequestParam(required = false) UUID assigneeUserId,
            @RequestParam(required = false) RemediationStatus status,
            @RequestParam(required = false) String ownedBy,
            @AuthenticationPrincipal AppUserPrincipal principal) {
        Set<UUID> productIdsIn = ownedByResolver.resolveProductIds(ownedBy, principal);
        return actionItemService.list(page, size, productId, assetId, assigneeUserId, status, productIdsIn);
    }

    @Operation(summary = "One action item in full, with every linked finding's own derived status")
    @GetMapping("/{id}")
    public ResponseEntity<ActionItemDetailResponse> detail(@PathVariable UUID id) {
        return actionItemService.detail(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Partially update an action item's status, assignment, title/description, or risk acceptance",
            description = """
                    Null fields are left untouched. Requesting NOT_AFFECTED is rejected (400) -- it is \
                    derived from VEX. Entering RISK_ACCEPTED requires riskAcceptedUntil (strictly \
                    future) and a non-blank riskAcceptanceJustification; leaving it clears every \
                    risk_* field. assigneeUserId and unassign=true can't both be set.""")
    @PatchMapping("/{id}")
    public ActionItemDetailResponse patch(@PathVariable UUID id, @RequestBody ActionItemPatchRequest request,
                                           @AuthenticationPrincipal AppUserPrincipal principal) {
        return actionItemService.patch(id, request, actingUser(principal));
    }

    @Operation(
            summary = "Attach one or more findings to an existing action item",
            description = "409 when the item's effective status is RISK_ACCEPTED/NOT_AFFECTED/RESOLVED "
                    + "(reopen or move to In progress first) or a finding is already linked elsewhere. "
                    + "400 for an unknown/PROVENANCE ref or a scope mismatch.")
    @PostMapping("/{id}/findings")
    public ActionItemDetailResponse attachFindings(@PathVariable UUID id, @Valid @RequestBody AttachFindingsRequest request,
                                                     @AuthenticationPrincipal AppUserPrincipal principal) {
        return actionItemService.attachFindings(id, request, actingUser(principal));
    }

    @Operation(
            summary = "Detach one finding from an action item",
            description = "Allowed in any status; an item may end with zero findings, its stored status stands.")
    @DeleteMapping("/{id}/findings/{type}/{findingId}")
    public ResponseEntity<Void> detachFinding(@PathVariable UUID id, @PathVariable FindingType type,
                                               @PathVariable UUID findingId) {
        actionItemService.detachFinding(id, type, findingId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Add a free-text comment to an action item, with no status change")
    @PostMapping("/{id}/comments")
    public ResponseEntity<ActionItemEventResponse> addComment(@PathVariable UUID id, @Valid @RequestBody AddCommentRequest request,
                                                                @AuthenticationPrincipal AppUserPrincipal principal) {
        ActionItemEventResponse response = actionItemService.addComment(id, request, actingUser(principal));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @Operation(summary = "One action item's history, oldest first")
    @GetMapping("/{id}/history")
    public List<ActionItemEventResponse> history(@PathVariable UUID id) {
        return actionItemService.history(id);
    }

    @Operation(
            summary = "Dispute a linked vulnerability finding with a VEX justification (M1k)",
            description = """
                    A dispute IS an authored TENANT OpenVEX not_affected statement, run through the \
                    existing M1f ingestion pipeline -- no new review mechanism, no new status logic. \
                    400 when findingId isn't linked to THIS item, is a non-vulnerability finding type \
                    (use RISK_ACCEPTED instead), is asset-derived, or impactStatement is blank. \
                    404 for an unknown item. No ownership/role check on who may dispute (Tenancy \
                    hardening's job). Takes effect immediately once the queued job finishes, no \
                    approval step.""")
    @PostMapping("/{id}/disputes")
    public ResponseEntity<DisputeResponse> dispute(@PathVariable UUID id, @RequestBody DisputeFindingRequest request,
                                                     @AuthenticationPrincipal AppUserPrincipal appUserPrincipal,
                                                     java.security.Principal principal) {
        DisputeResponse response = actionItemDisputeService.dispute(id, request, actingUser(appUserPrincipal), principal);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    /** The authenticated account behind the JWT, as the {@link User} entity the service attributes events to. */
    private User actingUser(AppUserPrincipal principal) {
        return userRepository.findById(principal.getId())
                .orElseThrow(() -> new NoSuchElementException("Authenticated user not found: " + principal.getId()));
    }

    @ExceptionHandler(InvalidActionItemException.class)
    public ResponseEntity<ErrorResponse> onInvalidActionItem(InvalidActionItemException e) {
        log.warn("Rejected action item request: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> onDataIntegrityViolation(DataIntegrityViolationException e) {
        log.warn("Action item change lost a race against a concurrent insert: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("that finding is already linked to another action item"));
    }

}
