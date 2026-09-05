package net.jdesive.secy.persistence.entity;

/**
 * Coarse-grained application role. Stored as a string in {@code app_user.role}, and mapped to the
 * Spring Security authority {@code ROLE_<name>}.
 *
 * <p>Single-tenant for now: {@link #ADMIN} is granted to the first account created on a fresh
 * install, everyone after that gets {@link #USER}.
 */
public enum Role {
    USER,
    ADMIN;

    /** The Spring Security authority string for this role. */
    public String authority() {
        return "ROLE_" + name();
    }
}
