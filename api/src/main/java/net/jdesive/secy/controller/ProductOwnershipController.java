package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.model.ownership.ProductOwnerRequest;
import net.jdesive.secy.model.ownership.ProductOwnerResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.security.AppUserPrincipal;
import net.jdesive.secy.service.InvalidOwnershipException;
import net.jdesive.secy.service.OwnershipService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@Slf4j
@Tag(name = "Ownership",
        description = "Who owns a product — manual links (M1b); inferred from CODEOWNERS/team permissions/cloud tags in M2/M3")
@RestController
@RequestMapping("/products/{productId}/owners")
@RequiredArgsConstructor
public class ProductOwnershipController {

    private final OwnershipService ownershipService;
    private final AppUserRepository userRepository;

    @Operation(summary = "List a product's ownership links")
    @GetMapping
    public List<ProductOwnerResponse> list(@PathVariable UUID productId) {
        return ownershipService.listProductOwners(productId);
    }

    // TODO(tenancy-hardening): restrict POST/DELETE to SECURITY_ENGINEER (M1k's role model:
    // TenantAccessService.accessFor — owner assignment/reassignment is that view's job).
    @Operation(summary = "Manually assign an owner to a product")
    @PostMapping
    public ResponseEntity<ProductOwnerResponse> assign(
            @PathVariable UUID productId,
            @RequestBody ProductOwnerRequest request,
            @AuthenticationPrincipal AppUserPrincipal principal) {
        User actingUser = principal == null ? null : userRepository.findById(principal.getId()).orElse(null);
        ProductOwnerResponse response = ownershipService.assignManualProductOwner(productId, request, actingUser);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // TODO(tenancy-hardening): restrict POST/DELETE to SECURITY_ENGINEER (M1k's role model:
    // TenantAccessService.accessFor — owner assignment/reassignment is that view's job).
    @Operation(summary = "Remove a manual ownership link")
    @DeleteMapping("/{ownerId}")
    public ResponseEntity<Void> remove(@PathVariable UUID productId, @PathVariable UUID ownerId) {
        ownershipService.removeManualProductOwner(productId, ownerId);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(InvalidOwnershipException.class)
    public ResponseEntity<ErrorResponse> onInvalidOwnership(InvalidOwnershipException e) {
        log.warn("Rejected ownership change: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> onDataIntegrityViolation(DataIntegrityViolationException e) {
        log.warn("Ownership change lost a race against a concurrent insert: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("that owner is already linked to this product"));
    }
}
