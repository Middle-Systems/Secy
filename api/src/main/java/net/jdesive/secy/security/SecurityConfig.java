package net.jdesive.secy.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Stateless bearer-token security for the whole API.
 *
 * <p>Everything is authenticated by default; the permit list below is the complete set of
 * anonymous surface:
 *
 * <ul>
 *   <li>{@code /auth/**} — you cannot log in with a token you do not have yet. {@code /auth/me}
 *       lives under this prefix and enforces its own 401 (see {@code AuthController}).</li>
 *   <li>{@code /actuator/health} — liveness probes. The rest of actuator stays protected.</li>
 *   <li>the OpenAPI spec and Swagger UI — the schema is not a secret and the browsable UI is how
 *       you get an <em>Authorize</em> button to try the protected endpoints.</li>
 * </ul>
 *
 * <p>No sessions, no CSRF token: there is no cookie to ride on, so a cross-site request cannot
 * carry credentials. Authentication comes entirely from the {@code Authorization} header, which an
 * attacker's page cannot set for someone else's browser.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    /** Anonymous endpoints. Adding to this list is a security decision — keep it short. */
    static final String[] PUBLIC_PATHS = {
            "/auth/**",
            "/actuator/health",
            "/actuator/health/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/v3/api-docs.yaml",
            "/swagger-ui.html",
            "/swagger-ui/**",
    };

    private final JwtService jwtService;
    private final AppUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> {})
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_PATHS).permitAll()
                        .anyRequest().authenticated())
                // Without this the default entry point answers 403; the UI needs a 401 to know it
                // should drop its token and send the user back to /login.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, userDetailsService),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * BCrypt at the default strength (10). Changing the strength does not invalidate existing
     * hashes — the cost factor is encoded in each digest.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Boot auto-configures a {@code DaoAuthenticationProvider} from the {@link
     * AppUserDetailsService} and {@link #passwordEncoder()} beans; this just exposes the resulting
     * manager so {@code AuthController} can run the login check through it.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
