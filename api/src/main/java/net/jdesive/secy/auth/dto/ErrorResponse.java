package net.jdesive.secy.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/** Flat error body for the auth endpoints — matches what the UI's {@code ApiError} reads. */
@Schema(description = "Error detail")
public record ErrorResponse(String message) {
}
