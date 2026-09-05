package net.jdesive.secy.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.auth.dto.AuthConfigResponse;
import net.jdesive.secy.auth.dto.AuthResponse;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.auth.dto.LoginRequest;
import net.jdesive.secy.auth.dto.RegisterRequest;
import net.jdesive.secy.auth.dto.UserResponse;
import net.jdesive.secy.security.AppUserPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Local email + password authentication.
 *
 * <p>The whole {@code /auth/**} prefix is anonymous in {@code SecurityConfig} — you cannot present
 * a token before you have one — so {@link #me(AppUserPrincipal)} enforces its own 401 rather than
 * relying on the filter chain.
 */
@Tag(name = "Auth", description = "Local accounts and bearer-token issuance")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "What the login screen may show before anyone signs in")
    @GetMapping("/config")
    public ResponseEntity<AuthConfigResponse> config() {
        return ResponseEntity.ok(new AuthConfigResponse(authService.isRegistrationEnabled()));
    }

    @Operation(summary = "Create a local account and sign in",
            description = "The first account created on an install becomes ADMIN; the rest are USER. "
                    + "Refused with 403 when secy.auth.registration-enabled is false.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Account created"),
            @ApiResponse(responseCode = "403", description = "Registration is disabled", content = @io.swagger.v3.oas.annotations.media.Content),
            @ApiResponse(responseCode = "409", description = "Email already registered", content = @io.swagger.v3.oas.annotations.media.Content),
    })
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @Operation(summary = "Exchange credentials for a bearer token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Signed in"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials", content = @io.swagger.v3.oas.annotations.media.Content),
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @Operation(summary = "The account behind the presented token",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The authenticated account"),
            @ApiResponse(responseCode = "401", description = "No or invalid token", content = @io.swagger.v3.oas.annotations.media.Content),
    })
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal AppUserPrincipal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(authService.currentUser(principal.getId()));
    }

    /**
     * Every credential failure comes back as the same flat 401, so the endpoint cannot be used to
     * tell a wrong password from a non-existent account.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> onAuthenticationFailure(AuthenticationException e) {
        String message = e instanceof DisabledException ? "Account is disabled" : "Invalid email or password";
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse(message));
    }
}
