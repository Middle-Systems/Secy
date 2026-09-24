package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.user.UserSummaryResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Read-only account listing for pickers — today, the Phase 7 triage assignee dropdown.
 *
 * <p>No admin gate: every path here already requires a valid JWT per {@code SecurityConfig}, and
 * "which accounts exist, by email and display name" is not sensitive within a single-tenant install
 * any authenticated user is already inside.
 */
@Tag(name = "Users", description = "Accounts, for pickers such as the triage assignee dropdown")
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final AppUserRepository userRepository;

    @Operation(summary = "List every enabled account",
            description = "id/email/displayName only — no role, no password hash.")
    @GetMapping
    public ResponseEntity<List<UserSummaryResponse>> list() {
        List<UserSummaryResponse> users = userRepository.findAll().stream()
                .filter(User::isEnabled)
                .map(UserSummaryResponse::from)
                .toList();
        return ResponseEntity.ok(users);
    }

}
