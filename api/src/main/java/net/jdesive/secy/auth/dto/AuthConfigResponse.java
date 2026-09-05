package net.jdesive.secy.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * What the login screen needs to know before anyone has authenticated. Anonymous by design, so it
 * must never grow anything that is not already obvious from trying the endpoints.
 */
@Schema(description = "Public auth configuration")
public record AuthConfigResponse(

        @Schema(description = "Whether POST /auth/register accepts new accounts")
        boolean registrationEnabled) {
}
