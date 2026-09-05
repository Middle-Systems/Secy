package net.jdesive.secy.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Turns {@code Authorization: Bearer <jwt>} into an authenticated {@code SecurityContext}.
 *
 * <p>Failure is always silent: a missing, malformed, expired or orphaned token simply leaves the
 * request anonymous, and the authorization rules in {@link SecurityConfig} decide whether that is
 * allowed. That keeps the permitted endpoints ({@code /auth/**}, the OpenAPI docs) reachable while
 * a stale token is sitting in someone's localStorage.
 *
 * <p>Deliberately not a bean: Spring Boot auto-registers any {@code Filter} bean with the servlet
 * container as well, which would run it a second time outside the security chain. {@link
 * SecurityConfig} constructs it by hand instead.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final AppUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Never overwrite an authentication another filter already established.
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            bearerToken(request)
                    .flatMap(jwtService::parse)
                    .ifPresent(claims -> authenticate(claims, request));
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(Claims claims, HttpServletRequest request) {
        jwtService.userId(claims)
                .flatMap(userDetailsService::loadById)
                .filter(AppUserPrincipal::isEnabled)
                .ifPresent(principal -> {
                    var authentication = new UsernamePasswordAuthenticationToken(
                            principal, null, principal.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                });
    }

    private static Optional<String> bearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }
}
