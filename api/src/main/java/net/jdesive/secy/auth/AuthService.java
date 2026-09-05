package net.jdesive.secy.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.AuthResponse;
import net.jdesive.secy.auth.dto.LoginRequest;
import net.jdesive.secy.auth.dto.RegisterRequest;
import net.jdesive.secy.auth.dto.UserResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.security.AppUserDetailsService;
import net.jdesive.secy.security.AuthProperties;
import net.jdesive.secy.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/** Registration, login and "who am I" — everything behind {@code /auth/**}. */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuthProperties properties;

    /**
     * Create an account and log straight into it.
     *
     * <p>Bootstrapping rule: the very first account on an install becomes {@link Role#ADMIN}, every
     * one after it {@link Role#USER}. That is what makes a fresh deployment usable without a seeded
     * password — whoever reaches the register form first owns the instance, so
     * {@code secy.auth.registration-enabled} should be turned off once the team is onboarded.
     *
     * <p>{@code synchronized} narrows the window where two simultaneous first registrations both
     * see an empty table and both become admin. It is a single-instance guard; the unique index on
     * {@code email} is the only cross-instance protection here, and promoting a second admin is a
     * far milder failure than a duplicate account.
     */
    @Transactional
    public synchronized AuthResponse register(RegisterRequest request) {
        if (!properties.isRegistrationEnabled()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Registration is disabled");
        }

        String email = AppUserDetailsService.normalize(request.email());
        if (users.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "An account with that email already exists");
        }

        boolean first = users.count() == 0;

        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setDisplayName(displayNameOrDefault(request.displayName(), email));
        user.setRole(first ? Role.ADMIN : Role.USER);
        user.setEnabled(true);

        User saved = users.save(user);
        log.info("Registered account {} with role {}", saved.getEmail(), saved.getRole());

        return tokenFor(saved);
    }

    /** Verify credentials through the {@code DaoAuthenticationProvider} and mint a token. */
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        String email = AppUserDetailsService.normalize(request.email());

        // Throws BadCredentialsException / DisabledException, which AuthController maps to 401.
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, request.password()));

        User user = users.findByEmail(email)
                // Authentication just succeeded, so this can only happen if the account was deleted
                // in between; treat it as a failed login rather than a 500.
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));

        return tokenFor(user);
    }

    /** The account behind an authenticated request. */
    @Transactional(readOnly = true)
    public UserResponse currentUser(UUID id) {
        return users.findById(id)
                .map(UserResponse::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account no longer exists"));
    }

    public boolean isRegistrationEnabled() {
        return properties.isRegistrationEnabled();
    }

    private AuthResponse tokenFor(User user) {
        JwtService.IssuedToken issued = jwtService.issue(user);
        return new AuthResponse(issued.token(), issued.expiresAt(), UserResponse.from(user));
    }

    private static String displayNameOrDefault(String displayName, String email) {
        if (displayName != null && !displayName.isBlank()) {
            return displayName.trim();
        }
        int at = email.indexOf('@');
        return at > 0 ? email.substring(0, at) : email;
    }
}
