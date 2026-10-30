package net.jdesive.secy.service.access;

import net.jdesive.secy.model.access.RoleSource;
import net.jdesive.secy.model.access.TenantAdminSource;
import net.jdesive.secy.persistence.entity.TenantRole;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * One user's computed access within one tenant (M1k) — {@code TenantAccessService.accessFor}'s
 * result, shared by {@code GET /me/access} and {@code GET /tenant/members}.
 */
public record TenantAccess(
        UUID tenantId,
        boolean member,
        boolean tenantAdmin,
        TenantAdminSource tenantAdminSource,
        Set<TenantRole> roles,
        RoleSource rolesSource,
        List<TenantRole> views,
        TenantRole defaultView) {
}
