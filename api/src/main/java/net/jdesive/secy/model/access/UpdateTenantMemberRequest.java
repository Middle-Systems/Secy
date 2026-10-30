package net.jdesive.secy.model.access;

import net.jdesive.secy.persistence.entity.TenantRole;

import java.util.List;

/**
 * {@code PATCH /tenant/members/{userId}} body (M1k). Mirrors {@code ActionItemPatchRequest}'s
 * assigneeUserId/unassign pattern: {@link #roles} and {@link #resetRolesToDefault} can't both be
 * set, and at least one field must be set. Null fields are left untouched.
 *
 * @param roles               replaces the member's stored role set exactly, including empty (means
 *                            "explicitly no views"); can't be combined with
 *                            {@link #resetRolesToDefault}{@code =true}
 * @param resetRolesToDefault clears any explicit role configuration, reverting to the unconfigured
 *                            default ({@code {SECURITY_ENGINEER}})
 * @param tenantAdmin         sets the stored {@code TenantMembership.tenantAdmin} flag
 */
public record UpdateTenantMemberRequest(
        List<TenantRole> roles,
        Boolean resetRolesToDefault,
        Boolean tenantAdmin) {
}
