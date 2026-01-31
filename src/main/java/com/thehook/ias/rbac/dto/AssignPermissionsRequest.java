package com.thehook.ias.rbac.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;
import java.util.UUID;

public record AssignPermissionsRequest(
        @NotEmpty(message = "At least one permission ID is required")
        Set<UUID> permissionIds
) {
}
