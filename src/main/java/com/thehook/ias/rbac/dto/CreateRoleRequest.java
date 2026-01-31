package com.thehook.ias.rbac.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateRoleRequest(
        @NotBlank(message = "Role name is required")
        @Size(min = 2, max = 100, message = "Role name must be between 2 and 100 characters")
        @Pattern(regexp = "^[A-Z][A-Z0-9_]*$", message = "Role name must be uppercase with underscores")
        String name,

        @Size(max = 500, message = "Description must not exceed 500 characters")
        String description
) {
}
