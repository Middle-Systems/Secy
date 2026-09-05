package net.jdesive.secy.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

/** Result of a successful {@code /auth/login} or {@code /auth/register}. */
@Schema(description = "A signed access token and the account it belongs to")
public record AuthResponse(

        @Schema(description = "Send as `Authorization: Bearer <token>`")
        String token,

        @Schema(description = "When the token stops being accepted (ISO-8601 instant)")
        Instant expiresAt,

        UserResponse user) {
}
