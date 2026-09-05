package net.jdesive.secy.security;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.AppUserRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Looks accounts up for the {@code DaoAuthenticationProvider} (login, by email) and for
 * {@link JwtAuthenticationFilter} (per request, by id).
 *
 * <p>Resolving the token's subject against the database on every request is a deliberate cost: it
 * is what makes a deleted or disabled account stop working immediately instead of at token expiry.
 */
@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository users;

    @Override
    @Transactional(readOnly = true)
    public AppUserPrincipal loadUserByUsername(String email) throws UsernameNotFoundException {
        return users.findByEmail(normalize(email))
                .map(AppUserPrincipal::new)
                // Same message whether the account is missing or the password is wrong — the caller
                // turns both into a flat 401 so the endpoint is not an account-existence oracle.
                .orElseThrow(() -> new UsernameNotFoundException("No account for " + email));
    }

    @Transactional(readOnly = true)
    public Optional<AppUserPrincipal> loadById(UUID id) {
        return users.findById(id).map(AppUserPrincipal::new);
    }

    /** Emails are matched case-insensitively; they are stored lower-cased on registration. */
    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
