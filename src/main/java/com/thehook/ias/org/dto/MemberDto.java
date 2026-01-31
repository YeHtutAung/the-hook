package com.thehook.ias.org.dto;

import com.thehook.ias.org.MembershipStatus;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record MemberDto(
        UUID membershipId,
        UUID userId,
        String email,
        String displayName,
        MembershipStatus status,
        Set<String> roles,
        Instant joinedAt
) {
}
