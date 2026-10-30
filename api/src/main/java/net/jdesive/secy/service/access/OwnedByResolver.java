package net.jdesive.secy.service.access;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.security.AppUserPrincipal;
import net.jdesive.secy.service.OwnershipService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Resolves {@code GET /action-items?ownedBy=}/{@code GET /findings?ownedBy=} into the product-id
 * restriction the two services apply (M1k — ROADMAP.md's "Role-based views" §6). Any authenticated
 * user may pass {@code ownedBy=<uuid>} for anyone — it is not role-tied, same as the rest of M1k's
 * views: composable, consistent with stateless view switching, and enforcement is Tenancy
 * hardening's job.
 *
 * <p>The first real caller of {@code OwnershipService.productIdsOwnedBy} outside a test (M1b shipped
 * it with "no caller yet").
 */
@Component
@RequiredArgsConstructor
public class OwnedByResolver {

    private final OwnershipService ownershipService;

    /**
     * @param ownedBy   {@code null}: no restriction (returns null). {@code "me"} (case-insensitive):
     *                  the authenticated principal — 401 if there is none. Otherwise parsed as a
     *                  UUID — 400 if it is neither.
     * @param principal the authenticated caller, or null under e.g. {@code @WithMockUser}
     * @return null for "no restriction", else the (possibly empty) set of product ids that user owns
     */
    public Set<UUID> resolveProductIds(String ownedBy, AppUserPrincipal principal) {
        if (ownedBy == null) {
            return null;
        }
        UUID userId;
        if (ownedBy.equalsIgnoreCase("me")) {
            if (principal == null) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "authentication required for ownedBy=me");
            }
            userId = principal.getId();
        } else {
            try {
                userId = UUID.fromString(ownedBy.trim());
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "ownedBy must be 'me' or a user UUID, got '" + ownedBy + "'");
            }
        }
        return new HashSet<>(ownershipService.productIdsOwnedBy(Tenant.DEFAULT_TENANT_ID, userId));
    }

}
