package net.jdesive.secy.model.access;

import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.TenantRole;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * One row of {@code GET /tenant/members} — every effective and stored access field for one member
 * of the default tenant (M1k). Any authenticated user may read this list (same "no admin gate"
 * reasoning as {@code UserController}); only {@code PATCH /tenant/members/{userId}} is gated.
 *
 * @param tenantAdmin       EFFECTIVE value
 * @param storedTenantAdmin the raw {@code TenantMembership.tenantAdmin} column, before the
 *                          global-admin override
 * @param roles             effective role set, in enum declaration order
 */
public record TenantMemberResponse(
        UUID userId,
        String email,
        String displayName,
        boolean enabled,
        Role globalRole,
        boolean tenantAdmin,
        TenantAdminSource tenantAdminSource,
        boolean storedTenantAdmin,
        List<TenantRole> roles,
        RoleSource rolesSource,
        LocalDateTime accessUpdatedAt,
        UUID accessUpdatedById) {
}
