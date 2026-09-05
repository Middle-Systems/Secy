package net.jdesive.secy.security;

import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.User;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Adapter between the {@link User} entity and Spring Security.
 *
 * <p>This is what {@code @AuthenticationPrincipal} hands a controller, so it deliberately carries
 * the fields a request handler needs (id, email, display name, role) and nothing else — in
 * particular it keeps the BCrypt hash only for the duration of an authentication check, and
 * {@link #eraseCredentials()} drops it afterwards.
 */
public class AppUserPrincipal implements UserDetails, CredentialsContainer {

    private final UUID id;
    private final String email;
    private final String displayName;
    private final Role role;
    private final boolean enabled;
    private String passwordHash;

    public AppUserPrincipal(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.displayName = user.getDisplayName();
        this.role = user.getRole();
        this.enabled = user.isEnabled();
        this.passwordHash = user.getPasswordHash();
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Role getRole() {
        return role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.authority()));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    /** The username is the email — accounts are identified by it everywhere in the UI and API. */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        this.passwordHash = null;
    }
}
