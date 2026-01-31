package com.thehook.ias.user;

import com.thehook.ias.org.OrganizationService;
import com.thehook.ias.org.dto.MembershipDto;
import com.thehook.ias.user.dto.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/me")
@RequiredArgsConstructor
@Tag(name = "Current User", description = "Operations for the authenticated user")
@SecurityRequirement(name = "oauth2")
public class UserController {

    private final UserService userService;
    private final OrganizationService organizationService;

    @GetMapping
    @Operation(
            summary = "Get current user profile",
            description = "Returns the authenticated user's profile information."
    )
    public UserDto getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        User user = userService.findById(userId);
        return userService.toDto(user);
    }

    @GetMapping("/memberships")
    @Operation(
            summary = "Get user's organization memberships",
            description = "Returns all active organization memberships for the current user, including roles."
    )
    public List<MembershipDto> getMemberships(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.getUserMemberships(userId);
    }

    private UUID getUserIdFromJwt(Jwt jwt) {
        String userId = jwt.getClaimAsString("user_id");
        if (userId != null) {
            return UUID.fromString(userId);
        }
        // Fallback to subject - shouldn't happen with proper token customizer
        throw new IllegalStateException("user_id claim not found in JWT");
    }
}
