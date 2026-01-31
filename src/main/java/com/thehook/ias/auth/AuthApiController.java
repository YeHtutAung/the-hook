package com.thehook.ias.auth;

import com.thehook.ias.user.UserService;
import com.thehook.ias.user.dto.RegisterRequest;
import com.thehook.ias.user.dto.RegisterResponse;
import com.thehook.ias.user.dto.VerifyEmailRequest;
import com.thehook.ias.user.dto.VerifyEmailResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST API endpoints for user registration and email verification.
 * These are public endpoints that don't require authentication.
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "User registration and email verification")
public class AuthApiController {

    private final UserService userService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Register a new user",
            description = """
                    Creates a new user account with email and password.
                    Returns a verification token that must be used to verify the email address.

                    **Note:** In production, the verification token would be sent via email.
                    For MVP/testing, the token is returned in the response.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request data",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "409", description = "Email already registered",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        String ipAddress = getClientIpAddress(httpRequest);
        log.info("Registration attempt for email: {} from IP: {}", request.email(), ipAddress);

        return userService.registerUser(request, ipAddress);
    }

    @PostMapping("/verify")
    @Operation(
            summary = "Verify email address",
            description = "Verifies a user's email address using the verification token received during registration."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public VerifyEmailResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        log.info("Email verification attempt with token: {}...",
                request.token().substring(0, Math.min(8, request.token().length())));

        return userService.verifyEmailWithResponse(request.token());
    }

    @GetMapping("/verify")
    @Operation(
            summary = "Verify email address (GET)",
            description = "Verifies a user's email address using token as query parameter. Useful for email links."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public VerifyEmailResponse verifyEmailGet(@RequestParam String token) {
        log.info("Email verification attempt (GET) with token: {}...",
                token.substring(0, Math.min(8, token.length())));

        return userService.verifyEmailWithResponse(token);
    }

    @PostMapping("/resend-verification")
    @Operation(
            summary = "Resend verification email",
            description = """
                    Resends the verification email to the specified address.
                    Only works for unverified accounts.

                    **Note:** For MVP/testing, returns the new verification token in the response.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Verification email sent"),
            @ApiResponse(responseCode = "400", description = "Email already verified or not found",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public Map<String, String> resendVerification(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        log.info("Resend verification requested for: {}", email);

        String newToken = userService.resendVerificationEmail(email);

        // For MVP: return token in response
        return Map.of(
                "message", "Verification email sent",
                "verificationToken", newToken
        );
    }

    /**
     * Extract client IP address, considering proxies.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Take the first IP in the chain (original client)
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
