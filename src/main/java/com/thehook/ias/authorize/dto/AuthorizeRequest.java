package com.thehook.ias.authorize.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record AuthorizeRequest(
        @NotNull(message = "User ID is required")
        UUID userId,

        @NotNull(message = "Organization ID is required")
        UUID orgId,

        @NotBlank(message = "Permission key is required")
        String permissionKey
) {
}
