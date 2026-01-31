package com.thehook.ias.org.dto;

import com.thehook.ias.org.InvitationStatus;

import java.time.Instant;
import java.util.UUID;

public record InvitationDto(
        UUID id,
        String email,
        String token,
        String roleName,
        InvitationStatus status,
        Instant expiresAt,
        Instant createdAt
) {
}
