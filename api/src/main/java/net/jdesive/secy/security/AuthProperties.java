package net.jdesive.secy.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Bound from the {@code # --- Auth ---} block in {@code application.properties}.
 *
 * <pre>
 * secy.auth.jwt.secret=${SECY_AUTH_JWT_SECRET:}
 * secy.auth.jwt.ttl=PT24H
 * secy.auth.registration-enabled=${SECY_AUTH_REGISTRATION_ENABLED:true}
 * </pre>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.auth")
public class AuthProperties {

    private final Jwt jwt = new Jwt();

    /** When false, {@code POST /auth/register} is refused with 403. */
    private boolean registrationEnabled = true;

    @Getter
    @Setter
    public static class Jwt {

        /**
         * HMAC-SHA256 signing secret; at least 32 bytes. Blank (the default) means "generate an
         * ephemeral one at startup", which keeps local dev zero-config at the cost of invalidating
         * every token on restart. Supply it via {@code SECY_AUTH_JWT_SECRET} in any real deployment
         * — never commit one.
         */
        private String secret = "";

        /** How long an issued token stays valid. */
        private Duration ttl = Duration.ofHours(24);
    }
}
