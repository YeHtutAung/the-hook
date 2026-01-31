package com.thehook.ias.rbac.dto;

import jakarta.validation.constraints.Size;

public record UpdateRoleRequest(
        @Size(max = 500, message = "Description must not exceed 500 characters")
        String description
) {
}
