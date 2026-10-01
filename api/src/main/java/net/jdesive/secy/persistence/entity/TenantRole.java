package net.jdesive.secy.persistence.entity;

/**
 * The per-tenant "views" a {@link TenantMembership} may hold (M1k — ROADMAP.md's "Role-based
 * views"). <b>These are VIEWS, not permissions.</b> They select which screens/filters a user sees
 * by default; M1k adds no enforcement anywhere — a user can still call any endpoint their JWT
 * authenticates them for, regardless of which (if any) of these roles their membership carries.
 * Real access control is the later "Tenancy hardening" milestone's job.
 *
 * <p>{@code TENANT_ADMIN} is deliberately not a value here — tenant-admin is a separate boolean
 * permission ({@link TenantMembership#isTenantAdmin()}), not a view: if it were a role in this set,
 * every view-list/switcher consumer would have to remember to filter it back out.
 */
public enum TenantRole {

    /** Aggregate, read-only posture views — see {@code LeadershipMetricsController}. */
    LEADERSHIP,

    /** The existing Actionable Items / triage / ownership / policy-tuning surface. The default. */
    SECURITY_ENGINEER,

    /** "My action items" scoped to the products a user owns — see {@code OwnedByResolver}. */
    SOFTWARE_ENGINEER

}
