package com.thehook.ias.org.dto;

import com.thehook.ias.org.MembershipStatus;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record MembershipDto(
        UUID id,
        UUID organizationId,
        String organizationName,
        String organizationSlug,
        MembershipStatus status,
        Set<String> roles,
        Instant createdAt
) {
}
