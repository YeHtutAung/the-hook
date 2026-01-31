package com.thehook.ias.org.dto;

import java.time.Instant;
import java.util.UUID;

public record OrganizationDto(
        UUID id,
        String name,
        String slug,
        boolean enabled,
        Instant createdAt
) {
}
