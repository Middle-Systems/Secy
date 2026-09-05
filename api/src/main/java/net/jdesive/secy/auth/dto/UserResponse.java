package net.jdesive.secy.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.User;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * The public projection of an account. Exists so {@code passwordHash} has no route to a response
 * body — the {@link User} entity is never serialized by the auth endpoints.
 */
@Schema(description = "An account, without credentials")
public record UserResponse(
        UUID id,
        String email,
        String displayName,
        Role role,
        boolean enabled,
        LocalDateTime createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                user.getRole(),
                user.isEnabled(),
                user.getCreatedAt());
    }
}
