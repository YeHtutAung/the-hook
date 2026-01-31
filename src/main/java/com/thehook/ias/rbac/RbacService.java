package com.thehook.ias.rbac;

import com.thehook.ias.authorize.AuthorizeCacheService;
import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.org.Membership;
import com.thehook.ias.org.MembershipRepository;
import com.thehook.ias.rbac.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class RbacService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final MembershipRepository membershipRepository;
    private final AuditService auditService;
    private final AuthorizeCacheService authorizeCacheService;

    // ========================================
    // Role Operations
    // ========================================

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAllWithPermissions().stream()
                .map(this::toRoleDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public RoleDto getRoleById(UUID id) {
        Role role = roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> IasException.notFound("Role", id));
        return toRoleDto(role);
    }

    @Transactional(readOnly = true)
    public Role getRoleByName(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> IasException.notFound("Role", name));
    }

    @Transactional(readOnly = true)
    public Role getRoleByNameWithPermissions(String name) {
        return roleRepository.findByNameWithPermissions(name)
                .orElseThrow(() -> IasException.notFound("Role", name));
    }

    @Transactional
    public RoleDto createRole(CreateRoleRequest request, UUID actorId, String ipAddress) {
        String normalizedName = request.name().toUpperCase().trim();

        if (roleRepository.existsByName(normalizedName)) {
            throw IasException.conflict("Role already exists: " + normalizedName);
        }

        Role role = Role.builder()
                .name(normalizedName)
                .description(request.description())
                .systemRole(false)
                .build();

        role = roleRepository.save(role);
        log.info("Role created: {} (ID: {}) by user {}", role.getName(), role.getId(), actorId);

        auditService.logRoleCreated(role.getId(), role.getName(), actorId, ipAddress);

        return toRoleDto(role);
    }

    @Transactional
    public RoleDto updateRole(UUID roleId, UpdateRoleRequest request, UUID actorId, String ipAddress) {
        Role role = roleRepository.findByIdWithPermissions(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (role.isSystemRole()) {
            throw IasException.forbidden("Cannot modify system role");
        }

        Map<String, Object> changes = new HashMap<>();

        if (request.description() != null && !request.description().equals(role.getDescription())) {
            changes.put("description", Map.of("old", role.getDescription(), "new", request.description()));
            role.setDescription(request.description());
        }

        role = roleRepository.save(role);
        log.info("Role updated: {} by user {}", role.getName(), actorId);

        if (!changes.isEmpty()) {
            auditService.logRoleUpdated(role.getId(), role.getName(), actorId, changes, ipAddress);
        }

        return toRoleDto(role);
    }

    @Transactional
    public void deleteRole(UUID roleId, UUID actorId, String ipAddress) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (role.isSystemRole()) {
            throw IasException.forbidden("Cannot delete system role");
        }

        // Check if role is in use
        if (membershipRepository.existsByRoleId(roleId)) {
            throw IasException.conflict("Cannot delete role that is assigned to members");
        }

        String roleName = role.getName();
        roleRepository.delete(role);
        log.info("Role deleted: {} by user {}", roleName, actorId);

        auditService.logRoleDeleted(roleId, roleName, actorId, ipAddress);
    }

    @Transactional
    public RoleDto assignPermissions(UUID roleId, Set<UUID> permissionIds, UUID actorId, String ipAddress) {
        Role role = roleRepository.findByIdWithPermissions(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (role.isSystemRole()) {
            throw IasException.forbidden("Cannot modify system role permissions");
        }

        Set<Permission> permissions = new HashSet<>(permissionRepository.findAllById(permissionIds));
        if (permissions.size() != permissionIds.size()) {
            throw IasException.badRequest("Some permission IDs are invalid");
        }

        // Find new permissions being added (capture existing permissions before modification)
        Set<Permission> existingPermissions = role.getPermissions();
        Set<Permission> newPermissions = permissions.stream()
                .filter(p -> !existingPermissions.contains(p))
                .collect(Collectors.toSet());

        role.getPermissions().addAll(permissions);
        Role savedRole = roleRepository.save(role);

        if (!newPermissions.isEmpty()) {
            List<String> permissionKeys = newPermissions.stream().map(Permission::getKey).toList();
            log.info("Permissions assigned to role {}: {}", savedRole.getName(), permissionKeys);
            auditService.logPermissionsAssignedToRole(savedRole.getId(), savedRole.getName(), permissionKeys, actorId, ipAddress);
            authorizeCacheService.evictAll();
        }

        return toRoleDto(savedRole);
    }

    @Transactional
    public RoleDto removePermissions(UUID roleId, Set<UUID> permissionIds, UUID actorId, String ipAddress) {
        Role role = roleRepository.findByIdWithPermissions(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (role.isSystemRole()) {
            throw IasException.forbidden("Cannot modify system role permissions");
        }

        Set<Permission> permissionsToRemove = role.getPermissions().stream()
                .filter(p -> permissionIds.contains(p.getId()))
                .collect(Collectors.toSet());

        role.getPermissions().removeAll(permissionsToRemove);
        role = roleRepository.save(role);

        if (!permissionsToRemove.isEmpty()) {
            List<String> permissionKeys = permissionsToRemove.stream().map(Permission::getKey).toList();
            log.info("Permissions removed from role {}: {}", role.getName(), permissionKeys);
            auditService.logPermissionsRemovedFromRole(role.getId(), role.getName(), permissionKeys, actorId, ipAddress);
            authorizeCacheService.evictAll();
        }

        return toRoleDto(role);
    }

    // ========================================
    // Permission Operations
    // ========================================

    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions() {
        return permissionRepository.findAllOrderByKey().stream()
                .map(this::toPermissionDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public PermissionDto getPermissionById(UUID id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> IasException.notFound("Permission", id));
        return toPermissionDto(permission);
    }

    @Transactional(readOnly = true)
    public Permission getPermissionByKey(String key) {
        return permissionRepository.findByKey(key)
                .orElseThrow(() -> IasException.notFound("Permission", key));
    }

    @Transactional
    public PermissionDto createPermission(CreatePermissionRequest request, UUID actorId, String ipAddress) {
        String normalizedKey = request.key().toLowerCase().trim();

        if (permissionRepository.existsByKey(normalizedKey)) {
            throw IasException.conflict("Permission already exists: " + normalizedKey);
        }

        // Validate permission key format (e.g., "resource:action")
        if (!normalizedKey.matches("^[a-z][a-z0-9]*:[a-z][a-z0-9]*(:[a-z][a-z0-9]*)*$")) {
            throw IasException.badRequest("Permission key must follow format 'resource:action' (e.g., 'org:read', 'member:role:assign')");
        }

        Permission permission = Permission.builder()
                .key(normalizedKey)
                .description(request.description())
                .build();

        permission = permissionRepository.save(permission);
        log.info("Permission created: {} (ID: {}) by user {}", permission.getKey(), permission.getId(), actorId);

        auditService.logPermissionCreated(permission.getId(), permission.getKey(), actorId, ipAddress);

        return toPermissionDto(permission);
    }

    @Transactional
    public PermissionDto updatePermission(UUID permissionId, UpdatePermissionRequest request, UUID actorId, String ipAddress) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> IasException.notFound("Permission", permissionId));

        Map<String, Object> changes = new HashMap<>();

        if (request.description() != null && !request.description().equals(permission.getDescription())) {
            changes.put("description", Map.of("old", permission.getDescription(), "new", request.description()));
            permission.setDescription(request.description());
        }

        permission = permissionRepository.save(permission);
        log.info("Permission updated: {} by user {}", permission.getKey(), actorId);

        if (!changes.isEmpty()) {
            auditService.logPermissionUpdated(permission.getId(), permission.getKey(), actorId, changes, ipAddress);
        }

        return toPermissionDto(permission);
    }

    @Transactional
    public void deletePermission(UUID permissionId, UUID actorId, String ipAddress) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> IasException.notFound("Permission", permissionId));

        // Check if permission is assigned to any role
        if (roleRepository.existsByPermissionId(permissionId)) {
            throw IasException.conflict("Cannot delete permission that is assigned to roles");
        }

        String permissionKey = permission.getKey();
        permissionRepository.delete(permission);
        log.info("Permission deleted: {} by user {}", permissionKey, actorId);

        auditService.logPermissionDeleted(permissionId, permissionKey, actorId, ipAddress);
    }

    // ========================================
    // Membership Role Operations
    // ========================================

    @Transactional
    public void assignRoleToMember(UUID membershipId, UUID roleId, UUID actorId, UUID orgId, String ipAddress) {
        Membership membership = membershipRepository.findById(membershipId)
                .orElseThrow(() -> IasException.notFound("Membership", membershipId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (membership.getRoles().contains(role)) {
            throw IasException.conflict("Member already has this role");
        }

        membership.getRoles().add(role);
        membershipRepository.save(membership);

        log.info("Role {} assigned to membership {} by user {}", role.getName(), membershipId, actorId);
        auditService.logRoleAssigned(membershipId, roleId, role.getName(), orgId, actorId, ipAddress);
        authorizeCacheService.evictUserOrgCache(membership.getUser().getId(), orgId);
    }

    @Transactional
    public void removeRoleFromMember(UUID membershipId, UUID roleId, UUID actorId, UUID orgId, String ipAddress) {
        Membership membership = membershipRepository.findById(membershipId)
                .orElseThrow(() -> IasException.notFound("Membership", membershipId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> IasException.notFound("Role", roleId));

        if (!membership.getRoles().contains(role)) {
            throw IasException.badRequest("Member does not have this role");
        }

        // Ensure member has at least one role
        if (membership.getRoles().size() <= 1) {
            throw IasException.badRequest("Cannot remove the last role from a member");
        }

        membership.getRoles().remove(role);
        membershipRepository.save(membership);

        log.info("Role {} removed from membership {} by user {}", role.getName(), membershipId, actorId);
        auditService.logRoleRemoved(membershipId, roleId, role.getName(), orgId, actorId, ipAddress);
        authorizeCacheService.evictUserOrgCache(membership.getUser().getId(), orgId);
    }

    // ========================================
    // Legacy methods for backwards compatibility
    // ========================================

    @Transactional
    public RoleDto createRole(CreateRoleRequest request) {
        return createRole(request, null, null);
    }

    @Transactional
    public RoleDto assignPermissions(UUID roleId, Set<UUID> permissionIds) {
        return assignPermissions(roleId, permissionIds, null, null);
    }

    @Transactional
    public PermissionDto createPermission(CreatePermissionRequest request) {
        return createPermission(request, null, null);
    }

    // ========================================
    // Mapping
    // ========================================

    public RoleDto toRoleDto(Role role) {
        Set<String> permissionKeys = role.getPermissions().stream()
                .map(Permission::getKey)
                .collect(Collectors.toSet());

        return new RoleDto(
                role.getId(),
                role.getName(),
                role.getDescription(),
                role.isSystemRole(),
                permissionKeys
        );
    }

    public PermissionDto toPermissionDto(Permission permission) {
        return new PermissionDto(
                permission.getId(),
                permission.getKey(),
                permission.getDescription()
        );
    }
}
