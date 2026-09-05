package net.jdesive.secy.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

/** Body of {@code POST /auth/register}. */
@Schema(description = "New local account")
public record RegisterRequest(

        @Schema(example = "analyst@example.com")
        @NotBlank(message = "email is required")
        @Email(message = "email must be a valid address")
        @Size(max = 255, message = "email must be at most 255 characters")
        String email,

        @Schema(description = "At least 8 characters. Stored as a BCrypt hash.", example = "correct horse battery")
        @NotBlank(message = "password is required")
        // The upper bound is not cosmetic: BCrypt silently truncates beyond 72 bytes, so anything
        // longer would give a false sense of strength.
        @Size(min = 8, max = 72, message = "password must be between 8 and 72 characters")
        String password,

        @Schema(description = "Optional; falls back to the local part of the email.", example = "Alex Analyst")
        @Size(max = 120, message = "displayName must be at most 120 characters")
        String displayName) {
}
