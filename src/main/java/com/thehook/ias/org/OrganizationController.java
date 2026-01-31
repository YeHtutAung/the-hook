package com.thehook.ias.org;

import com.thehook.ias.org.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/orgs")
@RequiredArgsConstructor
@Tag(name = "Organizations", description = "Organization and membership management")
@SecurityRequirement(name = "oauth2")
public class OrganizationController {

    private final OrganizationService organizationService;

    // ========================================
    // Organization Endpoints
    // ========================================

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Create organization",
            description = "Creates a new organization. The creator is automatically added as SELLER_ADMIN."
    )
    public OrganizationDto createOrganization(
            @Valid @RequestBody CreateOrganizationRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.createOrganization(request, userId, getClientIp(httpRequest));
    }

    @GetMapping("/{orgId}")
    @Operation(
            summary = "Get organization",
            description = "Retrieves organization details. Requires membership or platform owner status."
    )
    public OrganizationDto getOrganization(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.getOrganization(orgId, userId);
    }

    // ========================================
    // Member Endpoints
    // ========================================

    @GetMapping("/{orgId}/members")
    @Operation(
            summary = "List organization members",
            description = "Lists all active members of the organization. Requires member:read permission."
    )
    public List<MemberDto> listMembers(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.getOrganizationMembers(orgId, userId);
    }

    @GetMapping("/{orgId}/members/{memberId}")
    @Operation(
            summary = "Get member details",
            description = "Retrieves a specific member's details. Users can view their own membership."
    )
    public MembershipDto getMember(
            @PathVariable UUID orgId,
            @PathVariable UUID memberId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.getMembership(orgId, memberId, userId);
    }

    // ========================================
    // Invitation Endpoints
    // ========================================

    @PostMapping("/{orgId}/members/invite")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Invite member",
            description = "Creates an invitation for a user to join the organization. Requires member:invite permission."
    )
    public InvitationDto inviteMember(
            @PathVariable UUID orgId,
            @Valid @RequestBody InviteMemberRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.inviteMember(orgId, request, userId, getClientIp(httpRequest));
    }

    @PostMapping("/{orgId}/members/accept")
    @Operation(
            summary = "Accept invitation",
            description = "Accepts an invitation to join an organization using the invitation token."
    )
    public MembershipDto acceptInvitation(
            @PathVariable UUID orgId,
            @Valid @RequestBody AcceptInvitationRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.acceptInvitation(request, userId, getClientIp(httpRequest));
    }

    @GetMapping("/{orgId}/invitations")
    @Operation(
            summary = "List pending invitations",
            description = "Lists all pending invitations for the organization. Requires member:invite permission."
    )
    public List<InvitationDto> listInvitations(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = getUserIdFromJwt(jwt);
        return organizationService.getOrganizationInvitations(orgId, userId);
    }

    @DeleteMapping("/{orgId}/invitations/{invitationId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Cancel invitation",
            description = "Cancels a pending invitation. Requires member:invite permission."
    )
    public void cancelInvitation(
            @PathVariable UUID orgId,
            @PathVariable UUID invitationId,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        UUID userId = getUserIdFromJwt(jwt);
        organizationService.cancelInvitation(invitationId, userId, getClientIp(httpRequest));
    }

    @GetMapping("/invitations/lookup")
    @Operation(
            summary = "Lookup invitation by token",
            description = "Retrieves invitation details by token. Used to display invitation info before accepting."
    )
    public InvitationDto lookupInvitation(
            @Parameter(description = "Invitation token") @RequestParam String token) {
        return organizationService.getInvitationByToken(token);
    }

    // ========================================
    // Helper Methods
    // ========================================

    private UUID getUserIdFromJwt(Jwt jwt) {
        String userId = jwt.getClaimAsString("user_id");
        if (userId != null) {
            return UUID.fromString(userId);
        }
        // Fallback to subject (email) - shouldn't happen with proper token customizer
        throw new IllegalStateException("user_id claim not found in JWT");
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
