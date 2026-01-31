package com.thehook.ias.common.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    // ========================================
    // Core Logging Method
    // ========================================

    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String action, String entityType, UUID entityId, UUID actorId,
                    UUID organizationId, Map<String, Object> details, String ipAddress) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .action(action)
                    .entityType(entityType)
                    .entityId(entityId)
                    .actorId(actorId)
                    .organizationId(organizationId)
                    .details(details)
                    .ipAddress(ipAddress)
                    .build();
            auditLogRepository.save(auditLog);
            log.debug("Audit log created: {} on {} {}", action, entityType, entityId);
        } catch (Exception e) {
            log.error("Failed to create audit log: {} on {} {}", action, entityType, entityId, e);
        }
    }

    // ========================================
    // User Audit Methods
    // ========================================

    public void logUserRegistered(UUID userId, String ipAddress) {
        log("USER_REGISTERED", "User", userId, userId, null, null, ipAddress);
    }

    public void logUserEmailVerified(UUID userId, String ipAddress) {
        log("USER_EMAIL_VERIFIED", "User", userId, userId, null, null, ipAddress);
    }

    public void logUserDisabled(UUID userId, UUID actorId, String ipAddress) {
        log("USER_DISABLED", "User", userId, actorId, null, null, ipAddress);
    }

    public void logUserEnabled(UUID userId, UUID actorId, String ipAddress) {
        log("USER_ENABLED", "User", userId, actorId, null, null, ipAddress);
    }

    // ========================================
    // Organization Audit Methods
    // ========================================

    public void logOrganizationCreated(UUID orgId, UUID creatorId, String ipAddress) {
        log("ORG_CREATED", "Organization", orgId, creatorId, orgId, null, ipAddress);
    }

    public void logOrganizationUpdated(UUID orgId, UUID actorId, Map<String, Object> changes, String ipAddress) {
        log("ORG_UPDATED", "Organization", orgId, actorId, orgId, changes, ipAddress);
    }

    public void logOrganizationDisabled(UUID orgId, UUID actorId, String ipAddress) {
        log("ORG_DISABLED", "Organization", orgId, actorId, orgId, null, ipAddress);
    }

    // ========================================
    // Membership Audit Methods
    // ========================================

    public void logInvitationCreated(UUID invitationId, String email, UUID orgId, UUID actorId, String ipAddress) {
        log("INVITATION_CREATED", "Invitation", invitationId, actorId, orgId,
                Map.of("email", email), ipAddress);
    }

    public void logInvitationAccepted(UUID invitationId, UUID userId, UUID orgId, String ipAddress) {
        log("INVITATION_ACCEPTED", "Invitation", invitationId, userId, orgId, null, ipAddress);
    }

    public void logInvitationCancelled(UUID invitationId, UUID actorId, UUID orgId, String ipAddress) {
        log("INVITATION_CANCELLED", "Invitation", invitationId, actorId, orgId, null, ipAddress);
    }

    public void logMemberRemoved(UUID membershipId, UUID userId, UUID orgId, UUID actorId, String ipAddress) {
        log("MEMBER_REMOVED", "Membership", membershipId, actorId, orgId,
                Map.of("removedUserId", userId.toString()), ipAddress);
    }

    // ========================================
    // Role Assignment Audit Methods
    // ========================================

    public void logRoleAssigned(UUID membershipId, UUID roleId, String roleName, UUID orgId, UUID actorId, String ipAddress) {
        log("ROLE_ASSIGNED", "Membership", membershipId, actorId, orgId,
                Map.of("roleId", roleId.toString(), "roleName", roleName), ipAddress);
    }

    public void logRoleRemoved(UUID membershipId, UUID roleId, String roleName, UUID orgId, UUID actorId, String ipAddress) {
        log("ROLE_REMOVED", "Membership", membershipId, actorId, orgId,
                Map.of("roleId", roleId.toString(), "roleName", roleName), ipAddress);
    }

    // Legacy method for backwards compatibility
    public void logRoleAssignment(UUID membershipId, UUID roleId, UUID actorId, UUID orgId, String ipAddress) {
        log("ROLE_ASSIGNED", "Membership", membershipId, actorId, orgId,
                Map.of("roleId", roleId.toString()), ipAddress);
    }

    // ========================================
    // RBAC Admin Audit Methods
    // ========================================

    public void logRoleCreated(UUID roleId, String roleName, UUID actorId, String ipAddress) {
        log("ROLE_CREATED", "Role", roleId, actorId, null,
                Map.of("roleName", roleName), ipAddress);
    }

    public void logRoleUpdated(UUID roleId, String roleName, UUID actorId, Map<String, Object> changes, String ipAddress) {
        Map<String, Object> details = new java.util.HashMap<>(changes);
        details.put("roleName", roleName);
        log("ROLE_UPDATED", "Role", roleId, actorId, null, details, ipAddress);
    }

    public void logRoleDeleted(UUID roleId, String roleName, UUID actorId, String ipAddress) {
        log("ROLE_DELETED", "Role", roleId, actorId, null,
                Map.of("roleName", roleName), ipAddress);
    }

    public void logPermissionsAssignedToRole(UUID roleId, String roleName, Collection<String> permissionKeys, UUID actorId, String ipAddress) {
        log("PERMISSIONS_ASSIGNED", "Role", roleId, actorId, null,
                Map.of("roleName", roleName, "permissions", permissionKeys), ipAddress);
    }

    public void logPermissionsRemovedFromRole(UUID roleId, String roleName, Collection<String> permissionKeys, UUID actorId, String ipAddress) {
        log("PERMISSIONS_REMOVED", "Role", roleId, actorId, null,
                Map.of("roleName", roleName, "permissions", permissionKeys), ipAddress);
    }

    public void logPermissionCreated(UUID permissionId, String permissionKey, UUID actorId, String ipAddress) {
        log("PERMISSION_CREATED", "Permission", permissionId, actorId, null,
                Map.of("permissionKey", permissionKey), ipAddress);
    }

    public void logPermissionUpdated(UUID permissionId, String permissionKey, UUID actorId, Map<String, Object> changes, String ipAddress) {
        Map<String, Object> details = new java.util.HashMap<>(changes);
        details.put("permissionKey", permissionKey);
        log("PERMISSION_UPDATED", "Permission", permissionId, actorId, null, details, ipAddress);
    }

    public void logPermissionDeleted(UUID permissionId, String permissionKey, UUID actorId, String ipAddress) {
        log("PERMISSION_DELETED", "Permission", permissionId, actorId, null,
                Map.of("permissionKey", permissionKey), ipAddress);
    }
}
