package com.thehook.ias.rbac.dto;

import java.util.Set;
import java.util.UUID;

public record RoleDto(
        UUID id,
        String name,
        String description,
        boolean systemRole,
        Set<String> permissions
) {
}
