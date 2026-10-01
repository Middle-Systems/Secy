package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.model.access.MyAccessResponse;
import net.jdesive.secy.model.access.OwnedProductResponse;
import net.jdesive.secy.model.access.TenantMemberResponse;
import net.jdesive.secy.model.access.UpdateTenantMemberRequest;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.security.AppUserPrincipal;
import net.jdesive.secy.service.OwnershipService;
import net.jdesive.secy.service.access.InvalidTenantAccessException;
import net.jdesive.secy.service.access.TenantAccess;
import net.jdesive.secy.service.access.TenantAccessService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * M1k's role/membership surface (ROADMAP.md — "Role-based views"): {@code /me/**} answers "what can
 * I see", {@code /tenant/members} is the role-assignment admin surface.
 *
 * <p><b>No enforcement anywhere else.</b> {@code GET /me/access} and {@code GET /me/owned-products}
 * only read; {@code GET /tenant/members} is open to any authenticated user (same "no admin gate"
 * reasoning as {@code UserController}). {@code PATCH /tenant/members/{userId}} is the ONE
 * deliberate exception in this whole milestone — see {@code TenantAccessService}'s class Javadoc —
 * gated to an effective tenant admin because that gate is intrinsic to "roles are assigned per
 * tenant by tenant admins," not a retrofit onto an existing endpoint.
 */
@Slf4j
@Tag(name = "Tenant access", description = "M1k role/membership views — no enforcement on any other "
        + "endpoint; see the class Javadoc for the one deliberate exception")
@RestController
@RequiredArgsConstructor
public class TenantAccessController {

    private final TenantAccessService tenantAccessService;
    private final OwnershipService ownershipService;
    private final ProductRepository productRepository;

    @Operation(summary = "What the caller can see",
            description = "Stateless -- no current-view state is stored server-side. `defaultView` is "
                    + "the first of SECURITY_ENGINEER, SOFTWARE_ENGINEER, LEADERSHIP present in `roles`.")
    @GetMapping("/me/access")
    public MyAccessResponse myAccess(@AuthenticationPrincipal AppUserPrincipal principal) {
        requireAuthenticated(principal);
        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, principal.getId());
        return new MyAccessResponse(
                Tenant.DEFAULT_TENANT_ID, Tenant.DEFAULT_TENANT_NAME,
                access.member(), access.tenantAdmin(), access.tenantAdminSource(),
                access.views(), access.rolesSource(), access.views(), access.defaultView());
    }

    @Operation(summary = "The products the caller owns",
            description = "Products only -- M1b has no Repo entity and asset ownership has no writer "
                    + "until M3; team links with a free-text principal never resolve to a user.")
    @GetMapping("/me/owned-products")
    public List<OwnedProductResponse> myOwnedProducts(@AuthenticationPrincipal AppUserPrincipal principal) {
        requireAuthenticated(principal);
        List<UUID> productIds = ownershipService.productIdsOwnedBy(Tenant.DEFAULT_TENANT_ID, principal.getId());
        if (productIds.isEmpty()) {
            return List.of();
        }
        return productRepository.findAllById(productIds).stream()
                .map(p -> new OwnedProductResponse(p.getId(), p.getName()))
                .toList();
    }

    @Operation(summary = "Every member of the default tenant, with effective and stored access fields",
            description = "Any authenticated user may read this -- only the PATCH below is gated.")
    @GetMapping("/tenant/members")
    public List<TenantMemberResponse> members() {
        return tenantAccessService.listMembers(Tenant.DEFAULT_TENANT_ID);
    }

    @Operation(summary = "Set a member's tenant-admin flag and/or role set",
            description = "Gated to an effective tenant admin -- 403 otherwise. `roles` replaces the "
                    + "stored set exactly (empty allowed -- explicitly no views); `resetRolesToDefault=true` "
                    + "reverts to the unconfigured default; the two can't both be set. At least one of "
                    + "roles/resetRolesToDefault/tenantAdmin must be set.")
    @PatchMapping("/tenant/members/{userId}")
    public TenantMemberResponse updateMember(@PathVariable UUID userId,
                                              @RequestBody UpdateTenantMemberRequest request,
                                              @AuthenticationPrincipal AppUserPrincipal principal) {
        if (principal == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "tenant admin required");
        }
        tenantAccessService.requireTenantAdmin(Tenant.DEFAULT_TENANT_ID, principal.getId());
        return tenantAccessService.updateMember(Tenant.DEFAULT_TENANT_ID, userId, request, principal.getId());
    }

    private static void requireAuthenticated(AppUserPrincipal principal) {
        if (principal == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "authentication required");
        }
    }

    @ExceptionHandler(InvalidTenantAccessException.class)
    public ResponseEntity<ErrorResponse> onInvalid(InvalidTenantAccessException e) {
        log.warn("Rejected tenant access request: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

}
