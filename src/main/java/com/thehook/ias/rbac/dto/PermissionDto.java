package com.thehook.ias.rbac.dto;

import java.util.UUID;

public record PermissionDto(
        UUID id,
        String key,
        String description
) {
}
