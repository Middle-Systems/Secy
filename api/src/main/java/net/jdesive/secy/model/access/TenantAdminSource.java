package net.jdesive.secy.model.access;

/**
 * Why a user is an effective tenant admin (M1k) — see {@code TenantAccessService.accessFor}. When
 * both could apply (a global {@link net.jdesive.secy.persistence.entity.Role#ADMIN} whose membership
 * also stores {@code tenantAdmin=true}), {@link #GLOBAL_ADMIN} is reported.
 */
public enum TenantAdminSource {

    /** The membership row's own {@code tenantAdmin} flag is true. */
    MEMBERSHIP,

    /** The user's global {@link net.jdesive.secy.persistence.entity.Role} is {@code ADMIN} — always
     *  effectively a tenant admin of every tenant, regardless of the membership flag. */
    GLOBAL_ADMIN

}
