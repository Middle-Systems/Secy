package net.jdesive.secy.model.user;

import net.jdesive.secy.persistence.entity.User;

import java.util.UUID;

/**
 * The minimal projection of an account for a picker — the Phase 7 triage assignee dropdown, and
 * anything similar later. Deliberately smaller than {@code auth.dto.UserResponse}: no role, and
 * obviously never a password hash.
 */
public record UserSummaryResponse(UUID id, String email, String displayName) {

    public static UserSummaryResponse from(User user) {
        return new UserSummaryResponse(user.getId(), user.getEmail(), user.getDisplayName());
    }
}
