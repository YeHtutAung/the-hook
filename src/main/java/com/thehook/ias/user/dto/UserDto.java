package com.thehook.ias.user.dto;

import java.time.Instant;
import java.util.UUID;

public record UserDto(
        UUID id,
        String email,
        String displayName,
        boolean emailVerified,
        boolean platformOwner,
        Instant createdAt
) {
}
