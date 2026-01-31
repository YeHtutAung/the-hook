package com.thehook.ias.rbac.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreatePermissionRequest(
        @NotBlank(message = "Permission key is required")
        @Size(min = 2, max = 100, message = "Permission key must be between 2 and 100 characters")
        @Pattern(regexp = "^[a-z][a-z0-9:_]*$", message = "Permission key must be lowercase with colons and underscores")
        String key,

        @Size(max = 500, message = "Description must not exceed 500 characters")
        String description
) {
}
