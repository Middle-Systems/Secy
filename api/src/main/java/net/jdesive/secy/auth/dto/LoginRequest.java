package net.jdesive.secy.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/** Body of {@code POST /auth/login}. */
@Schema(description = "Local account credentials")
public record LoginRequest(

        @Schema(example = "analyst@example.com")
        @NotBlank(message = "email is required")
        String email,

        @NotBlank(message = "password is required")
        String password) {
}
