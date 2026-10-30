package net.jdesive.secy.model.access;

/**
 * Where a membership's effective {@link net.jdesive.secy.persistence.entity.TenantRole} set came
 * from (M1k) — see {@code TenantAccessService.DEFAULT_ROLES}.
 */
public enum RoleSource {

    /** {@code rolesConfigured=false} — the unconfigured default, {@code {SECURITY_ENGINEER}}. */
    DEFAULT,

    /** {@code rolesConfigured=true} — a tenant admin set this membership's roles explicitly,
     *  possibly to an empty set ("no views, ask your tenant admin"). */
    EXPLICIT

}
