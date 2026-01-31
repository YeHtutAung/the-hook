package com.thehook.ias.org;

import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.org.dto.*;
import com.thehook.ias.rbac.Permission;
import com.thehook.ias.rbac.Role;
import com.thehook.ias.rbac.RoleRepository;
import com.thehook.ias.user.User;
import com.thehook.ias.user.UserRepository;
import com.thehook.ias.user.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final MembershipRepository membershipRepository;
    private final InvitationRepository invitationRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final EmailService emailService;

    @Value("${ias.base-url:http://localhost:9000}")
    private String baseUrl;

    @Value("${ias.invitation.expiry-days:7}")
    private int invitationExpiryDays;

    // ========================================
    // Organization Operations
    // ========================================

    @Transactional
    public OrganizationDto createOrganization(CreateOrganizationRequest request, UUID creatorId, String ipAddress) {
        String normalizedSlug = request.slug().toLowerCase().trim();

        if (organizationRepository.existsBySlug(normalizedSlug)) {
            throw IasException.conflict("Organization slug already exists: " + normalizedSlug);
        }

        // Verify creator exists
        User creator = userRepository.findById(creatorId)
                .orElseThrow(() -> IasException.notFound("User", creatorId));

        Organization org = Organization.builder()
                .name(request.name().trim())
                .slug(normalizedSlug)
                .enabled(true)
                .createdBy(creatorId)
                .build();

        org = organizationRepository.save(org);
        log.info("Organization created: {} (ID: {}) by user {}", org.getSlug(), org.getId(), creatorId);

        // Auto-add creator as SELLER_ADMIN
        Role sellerAdminRole = roleRepository.findByName(Role.SELLER_ADMIN)
                .orElseThrow(() -> IasException.notFound("Role", Role.SELLER_ADMIN));

        Membership membership = Membership.builder()
                .user(creator)
                .organization(org)
                .status(MembershipStatus.ACTIVE)
                .roles(Set.of(sellerAdminRole))
                .build();

        membershipRepository.save(membership);
        log.info("Creator {} added as SELLER_ADMIN to org {}", creatorId, org.getSlug());

        auditService.logOrganizationCreated(org.getId(), creatorId, ipAddress);

        return toOrganizationDto(org);
    }

    @Transactional(readOnly = true)
    public OrganizationDto getOrganization(UUID orgId, UUID requesterId) {
        Organization org = findById(orgId);

        // Check if requester is a member or platform owner
        User requester = userRepository.findById(requesterId)
                .orElseThrow(() -> IasException.notFound("User", requesterId));

        if (!requester.isPlatformOwner()) {
            verifyMembership(requesterId, orgId, "org:read");
        }

        return toOrganizationDto(org);
    }

    @Transactional(readOnly = true)
    public Organization findById(UUID id) {
        return organizationRepository.findById(id)
                .orElseThrow(() -> IasException.notFound("Organization", id));
    }

    @Transactional(readOnly = true)
    public Organization findBySlug(String slug) {
        return organizationRepository.findBySlug(slug.toLowerCase())
                .orElseThrow(() -> IasException.notFound("Organization", slug));
    }

    // ========================================
    // Membership Operations
    // ========================================

    @Transactional(readOnly = true)
    public List<MembershipDto> getUserMemberships(UUID userId) {
        return membershipRepository.findActiveByUserId(userId).stream()
                .map(this::toMembershipDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<MemberDto> getOrganizationMembers(UUID orgId, UUID requesterId) {
        // Check permission
        User requester = userRepository.findById(requesterId)
                .orElseThrow(() -> IasException.notFound("User", requesterId));

        if (!requester.isPlatformOwner()) {
            verifyMembership(requesterId, orgId, "member:read");
        }

        return membershipRepository.findActiveByOrgId(orgId).stream()
                .map(this::toMemberDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public MembershipDto getMembership(UUID orgId, UUID userId, UUID requesterId) {
        // Check permission (user can view their own membership or needs member:read)
        User requester = userRepository.findById(requesterId)
                .orElseThrow(() -> IasException.notFound("User", requesterId));

        if (!requester.isPlatformOwner() && !requesterId.equals(userId)) {
            verifyMembership(requesterId, orgId, "member:read");
        }

        Membership membership = membershipRepository.findActiveByUserIdAndOrgId(userId, orgId)
                .orElseThrow(() -> IasException.notFound("Membership", userId));

        return toMembershipDto(membership);
    }

    /**
     * Verify that a user has an active membership in an organization
     * and optionally check for a specific permission.
     */
    @Transactional(readOnly = true)
    public void verifyMembership(UUID userId, UUID orgId, String requiredPermission) {
        // First check if user is platform owner (bypasses all checks)
        User user = userRepository.findById(userId).orElse(null);
        if (user != null && user.isPlatformOwner()) {
            log.debug("Platform owner {} bypasses membership check for org {}", userId, orgId);
            return;
        }

        Membership membership = membershipRepository.findActiveByUserIdAndOrgId(userId, orgId)
                .orElseThrow(() -> IasException.forbidden("Not a member of this organization"));

        if (!membership.isActive()) {
            throw IasException.forbidden("Membership is not active");
        }

        if (requiredPermission != null) {
            boolean hasPermission = membership.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())
                    .map(Permission::getKey)
                    .anyMatch(key -> key.equals(requiredPermission));

            if (!hasPermission) {
                log.warn("User {} missing permission {} in org {}", userId, requiredPermission, orgId);
                throw IasException.forbidden("Missing required permission: " + requiredPermission);
            }
        }
    }

    /**
     * Check if user has a specific permission in an organization.
     * Returns false instead of throwing exception.
     */
    @Transactional(readOnly = true)
    public boolean hasPermission(UUID userId, UUID orgId, String permissionKey) {
        User user = userRepository.findById(userId).orElse(null);
        if (user != null && user.isPlatformOwner()) {
            return true;
        }

        return membershipRepository.findActiveByUserIdAndOrgId(userId, orgId)
                .map(membership -> membership.getRoles().stream()
                        .flatMap(role -> role.getPermissions().stream())
                        .map(Permission::getKey)
                        .anyMatch(key -> key.equals(permissionKey)))
                .orElse(false);
    }

    // ========================================
    // Invitation Operations
    // ========================================

    @Transactional
    public InvitationDto inviteMember(UUID orgId, InviteMemberRequest request, UUID inviterId, String ipAddress) {
        String normalizedEmail = request.email().toLowerCase().trim();

        // Verify inviter has permission
        verifyMembership(inviterId, orgId, "member:invite");

        Organization org = findById(orgId);

        // Verify organization is enabled
        if (!org.isEnabled()) {
            throw IasException.badRequest("Organization is disabled");
        }

        Role role = roleRepository.findById(request.roleId())
                .orElseThrow(() -> IasException.notFound("Role", request.roleId()));

        // Check if there's already a pending invitation
        if (invitationRepository.existsByOrganizationIdAndEmailAndStatus(orgId, normalizedEmail, InvitationStatus.PENDING)) {
            throw IasException.conflict("Pending invitation already exists for this email");
        }

        // Check if user is already a member
        userRepository.findByEmail(normalizedEmail).ifPresent(user -> {
            if (membershipRepository.existsByUserIdAndOrganizationId(user.getId(), orgId)) {
                throw IasException.conflict("User is already a member of this organization");
            }
        });

        User inviter = userRepository.findById(inviterId)
                .orElseThrow(() -> IasException.notFound("User", inviterId));

        Invitation invitation = Invitation.builder()
                .organization(org)
                .email(normalizedEmail)
                .token(UUID.randomUUID().toString())
                .role(role)
                .status(InvitationStatus.PENDING)
                .expiresAt(Instant.now().plus(invitationExpiryDays, ChronoUnit.DAYS))
                .createdBy(inviterId)
                .build();

        invitation = invitationRepository.save(invitation);
        log.info("Invitation created for {} to org {} (ID: {}) by {}", normalizedEmail, org.getSlug(), invitation.getId(), inviterId);

        // Send invitation email
        String inviteUrl = baseUrl + "/orgs/" + orgId + "/members/accept?token=" + invitation.getToken();
        emailService.sendInvitationEmail(normalizedEmail, org.getName(), inviter.getDisplayName(), inviteUrl);

        return toInvitationDto(invitation);
    }

    @Transactional
    public MembershipDto acceptInvitation(AcceptInvitationRequest request, UUID userId, String ipAddress) {
        Invitation invitation = invitationRepository.findByToken(request.token())
                .orElseThrow(() -> IasException.badRequest("Invalid invitation token"));

        if (!invitation.isPending()) {
            throw IasException.badRequest("Invitation is no longer pending");
        }

        if (invitation.isExpired()) {
            invitation.setStatus(InvitationStatus.EXPIRED);
            invitationRepository.save(invitation);
            throw IasException.badRequest("Invitation has expired");
        }

        // Verify organization is enabled
        if (!invitation.getOrganization().isEnabled()) {
            throw IasException.badRequest("Organization is disabled");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> IasException.notFound("User", userId));

        // Verify email matches (case-insensitive)
        if (!user.getEmail().equalsIgnoreCase(invitation.getEmail())) {
            throw IasException.forbidden("Invitation email does not match your account");
        }

        UUID orgId = invitation.getOrganization().getId();

        // Check if already a member
        if (membershipRepository.existsByUserIdAndOrganizationId(userId, orgId)) {
            throw IasException.conflict("Already a member of this organization");
        }

        // Create membership
        Membership membership = Membership.builder()
                .user(user)
                .organization(invitation.getOrganization())
                .status(MembershipStatus.ACTIVE)
                .roles(Set.of(invitation.getRole()))
                .build();

        membership = membershipRepository.save(membership);

        // Update invitation
        invitation.setStatus(InvitationStatus.ACCEPTED);
        invitation.setAcceptedAt(Instant.now());
        invitation.setAcceptedBy(userId);
        invitationRepository.save(invitation);

        log.info("User {} accepted invitation to org {} (membership ID: {})",
                userId, invitation.getOrganization().getSlug(), membership.getId());
        auditService.logInvitationAccepted(invitation.getId(), userId, orgId, ipAddress);

        return toMembershipDto(membership);
    }

    @Transactional(readOnly = true)
    public InvitationDto getInvitationByToken(String token) {
        Invitation invitation = invitationRepository.findByToken(token)
                .orElseThrow(() -> IasException.notFound("Invitation", token));
        return toInvitationDto(invitation);
    }

    @Transactional(readOnly = true)
    public List<InvitationDto> getOrganizationInvitations(UUID orgId, UUID requesterId) {
        // Check permission
        verifyMembership(requesterId, orgId, "member:invite");

        return invitationRepository.findByOrganizationIdAndStatus(orgId, InvitationStatus.PENDING).stream()
                .map(this::toInvitationDto)
                .toList();
    }

    @Transactional
    public void cancelInvitation(UUID invitationId, UUID requesterId, String ipAddress) {
        Invitation invitation = invitationRepository.findById(invitationId)
                .orElseThrow(() -> IasException.notFound("Invitation", invitationId));

        // Check permission
        verifyMembership(requesterId, invitation.getOrganization().getId(), "member:invite");

        if (!invitation.isPending()) {
            throw IasException.badRequest("Invitation is no longer pending");
        }

        invitation.setStatus(InvitationStatus.REVOKED);
        invitationRepository.save(invitation);

        log.info("Invitation {} cancelled by user {}", invitationId, requesterId);
    }

    // ========================================
    // Mapping
    // ========================================

    public OrganizationDto toOrganizationDto(Organization org) {
        return new OrganizationDto(
                org.getId(),
                org.getName(),
                org.getSlug(),
                org.isEnabled(),
                org.getCreatedAt()
        );
    }

    public MembershipDto toMembershipDto(Membership membership) {
        Set<String> roleNames = membership.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new MembershipDto(
                membership.getId(),
                membership.getOrganization().getId(),
                membership.getOrganization().getName(),
                membership.getOrganization().getSlug(),
                membership.getStatus(),
                roleNames,
                membership.getCreatedAt()
        );
    }

    public MemberDto toMemberDto(Membership membership) {
        Set<String> roleNames = membership.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new MemberDto(
                membership.getId(),
                membership.getUser().getId(),
                membership.getUser().getEmail(),
                membership.getUser().getDisplayName(),
                membership.getStatus(),
                roleNames,
                membership.getCreatedAt()
        );
    }

    public InvitationDto toInvitationDto(Invitation invitation) {
        return new InvitationDto(
                invitation.getId(),
                invitation.getEmail(),
                invitation.getToken(),
                invitation.getRole().getName(),
                invitation.getStatus(),
                invitation.getExpiresAt(),
                invitation.getCreatedAt()
        );
    }
}
