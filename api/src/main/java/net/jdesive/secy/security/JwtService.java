package net.jdesive.secy.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.User;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and verifies the HS256 access tokens used by {@link JwtAuthenticationFilter}.
 *
 * <p>Token shape: {@code sub} is the user's UUID (the stable identifier — an email change must not
 * invalidate nothing more than it has to), plus {@code email} and {@code role} claims so the
 * frontend can render without an extra round trip. Nothing secret goes in the payload; a JWT is
 * signed, not encrypted.
 *
 * <p>Sessions are stateless: there is no server-side revocation list, so a token stays valid until
 * {@code secy.auth.jwt.ttl} expires it. Rotating {@code SECY_AUTH_JWT_SECRET} invalidates all of
 * them at once, which is the blunt instrument available for now.
 */
@Slf4j
@Service
public class JwtService {

    /** HS256 requires a key of at least 256 bits. */
    private static final int MIN_SECRET_BYTES = 32;

    static final String CLAIM_EMAIL = "email";
    static final String CLAIM_ROLE = "role";

    private final SecretKey key;
    private final Duration ttl;

    public JwtService(AuthProperties properties) {
        this.ttl = properties.getJwt().getTtl();
        this.key = resolveKey(properties.getJwt().getSecret());
    }

    private static SecretKey resolveKey(String configured) {
        if (configured == null || configured.isBlank()) {
            log.warn("secy.auth.jwt.secret is not set — generating a random 256-bit signing key for "
                    + "this process. Issued tokens will NOT survive a restart. Set "
                    + "SECY_AUTH_JWT_SECRET before deploying.");
            return Jwts.SIG.HS256.key().build();
        }

        byte[] bytes = configured.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("secy.auth.jwt.secret must be at least " + MIN_SECRET_BYTES
                    + " bytes (256 bits) for HS256; got " + bytes.length);
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    /** Issue a token for {@code user}, valid for {@code secy.auth.jwt.ttl} from now. */
    public IssuedToken issue(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);

        String token = Jwts.builder()
                .subject(user.getId().toString())
                .claim(CLAIM_EMAIL, user.getEmail())
                .claim(CLAIM_ROLE, user.getRole().name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(key)
                .compact();

        return new IssuedToken(token, expiresAt);
    }

    /**
     * Verify the signature and expiry of {@code token}.
     *
     * @return the parsed claims, or empty if the token is malformed, expired or not signed by us.
     *         Callers treat every failure the same way — anonymous — so the reason is only logged.
     */
    public Optional<Claims> parse(String token) {
        try {
            return Optional.of(Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload());
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Rejected JWT: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /** The user id carried by a set of verified claims. */
    public Optional<UUID> userId(Claims claims) {
        try {
            return Optional.of(UUID.fromString(claims.getSubject()));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }

    /** The role claim, defaulting to {@link Role#USER} if it is missing or unrecognised. */
    public Role role(Claims claims) {
        String raw = claims.get(CLAIM_ROLE, String.class);
        try {
            return raw == null ? Role.USER : Role.valueOf(raw);
        } catch (IllegalArgumentException e) {
            return Role.USER;
        }
    }

    /** A freshly signed token together with the instant it stops being accepted. */
    public record IssuedToken(String token, Instant expiresAt) {
    }
}
