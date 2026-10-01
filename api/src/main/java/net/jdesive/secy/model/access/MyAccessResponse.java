package net.jdesive.secy.model.access;

import net.jdesive.secy.persistence.entity.TenantRole;

import java.util.List;
import java.util.UUID;

/**
 * {@code GET /me/access} — M1k's stateless "which views may I pick" answer (ROADMAP.md, "Role-based
 * views" §4). No current-view state lives here or anywhere server-side; the UI keeps that in
 * {@code localStorage}, validated against {@link #views} on load.
 *
 * @param member           whether the caller has a {@code TenantMembership} in this tenant at all
 * @param tenantAdmin      the EFFECTIVE value — {@code membership.tenantAdmin || globalRole==ADMIN}
 * @param tenantAdminSource null unless {@link #tenantAdmin} is true
 * @param roles            the caller's effective role set, in enum declaration order
 * @param rolesSource      {@code DEFAULT} (unconfigured membership) or {@code EXPLICIT}
 * @param views            identical to {@link #roles} today — every M1k role is exactly one view
 * @param defaultView      first of SECURITY_ENGINEER, SOFTWARE_ENGINEER, LEADERSHIP present in
 *                         {@link #roles}, or null when none are
 */
public record MyAccessResponse(
        UUID tenantId,
        String tenantName,
        boolean member,
        boolean tenantAdmin,
        TenantAdminSource tenantAdminSource,
        List<TenantRole> roles,
        RoleSource rolesSource,
        List<TenantRole> views,
        TenantRole defaultView) {
}
