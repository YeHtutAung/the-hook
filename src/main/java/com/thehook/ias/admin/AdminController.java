package com.thehook.ias.admin;

import com.thehook.ias.rbac.RbacService;
import com.thehook.ias.rbac.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@Tag(name = "Admin", description = "Platform administration (PLATFORM_OWNER only)")
@SecurityRequirement(name = "oauth2")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AdminController {

    private final RbacService rbacService;

    // ========================================
    // Role Management
    // ========================================

    @GetMapping("/roles")
    @Operation(summary = "List all roles", description = "Returns all roles with their assigned permissions")
    public List<RoleDto> listRoles() {
        return rbacService.getAllRoles();
    }

    @GetMapping("/roles/{id}")
    @Operation(summary = "Get role by ID", description = "Returns a specific role with its permissions")
    public RoleDto getRole(@PathVariable UUID id) {
        return rbacService.getRoleById(id);
    }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a new role", description = "Creates a custom role (non-system role)")
    public RoleDto createRole(
            @Valid @RequestBody CreateRoleRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.createRole(request, getActorId(jwt), getIpAddress(httpRequest));
    }

    @PutMapping("/roles/{id}")
    @Operation(summary = "Update a role", description = "Updates a role's description (cannot modify system roles)")
    public RoleDto updateRole(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateRoleRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.updateRole(id, request, getActorId(jwt), getIpAddress(httpRequest));
    }

    @DeleteMapping("/roles/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete a role", description = "Deletes a custom role (cannot delete system roles or roles assigned to members)")
    public void deleteRole(
            @PathVariable UUID id,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        rbacService.deleteRole(id, getActorId(jwt), getIpAddress(httpRequest));
    }

    @PostMapping("/roles/{id}/permissions")
    @Operation(summary = "Assign permissions to a role", description = "Adds permissions to a role")
    public RoleDto assignPermissions(
            @PathVariable UUID id,
            @Valid @RequestBody AssignPermissionsRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.assignPermissions(id, request.permissionIds(), getActorId(jwt), getIpAddress(httpRequest));
    }

    @DeleteMapping("/roles/{id}/permissions")
    @Operation(summary = "Remove permissions from a role", description = "Removes permissions from a role")
    public RoleDto removePermissions(
            @PathVariable UUID id,
            @Valid @RequestBody AssignPermissionsRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.removePermissions(id, request.permissionIds(), getActorId(jwt), getIpAddress(httpRequest));
    }

    // ========================================
    // Permission Management
    // ========================================

    @GetMapping("/permissions")
    @Operation(summary = "List all permissions", description = "Returns all permissions ordered by key")
    public List<PermissionDto> listPermissions() {
        return rbacService.getAllPermissions();
    }

    @GetMapping("/permissions/{id}")
    @Operation(summary = "Get permission by ID")
    public PermissionDto getPermission(@PathVariable UUID id) {
        return rbacService.getPermissionById(id);
    }

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a new permission", description = "Creates a new permission with format 'resource:action'")
    public PermissionDto createPermission(
            @Valid @RequestBody CreatePermissionRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.createPermission(request, getActorId(jwt), getIpAddress(httpRequest));
    }

    @PutMapping("/permissions/{id}")
    @Operation(summary = "Update a permission", description = "Updates a permission's description")
    public PermissionDto updatePermission(
            @PathVariable UUID id,
            @Valid @RequestBody UpdatePermissionRequest request,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        return rbacService.updatePermission(id, request, getActorId(jwt), getIpAddress(httpRequest));
    }

    @DeleteMapping("/permissions/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete a permission", description = "Deletes a permission (cannot delete if assigned to roles)")
    public void deletePermission(
            @PathVariable UUID id,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        rbacService.deletePermission(id, getActorId(jwt), getIpAddress(httpRequest));
    }

    // ========================================
    // Membership Role Management
    // ========================================

    @PostMapping("/memberships/{membershipId}/roles/{roleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Assign role to member", description = "Assigns a role to a membership")
    public void assignRoleToMember(
            @PathVariable UUID membershipId,
            @PathVariable UUID roleId,
            @RequestParam UUID orgId,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        rbacService.assignRoleToMember(membershipId, roleId, getActorId(jwt), orgId, getIpAddress(httpRequest));
    }

    @DeleteMapping("/memberships/{membershipId}/roles/{roleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Remove role from member", description = "Removes a role from a membership (member must retain at least one role)")
    public void removeRoleFromMember(
            @PathVariable UUID membershipId,
            @PathVariable UUID roleId,
            @RequestParam UUID orgId,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        rbacService.removeRoleFromMember(membershipId, roleId, getActorId(jwt), orgId, getIpAddress(httpRequest));
    }

    // ========================================
    // Helper Methods
    // ========================================

    private UUID getActorId(Jwt jwt) {
        String userId = jwt.getClaimAsString("user_id");
        if (userId != null) {
            return UUID.fromString(userId);
        }
        throw new IllegalStateException("user_id claim not found in JWT");
    }

    private String getIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
