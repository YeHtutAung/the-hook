package com.thehook.ias.user.dto;

import java.util.UUID;

public record VerifyEmailResponse(
        UUID userId,
        String email,
        boolean emailVerified,
        String message
) {
    public static VerifyEmailResponse success(UUID userId, String email) {
        return new VerifyEmailResponse(
                userId,
                email,
                true,
                "Email verified successfully. You can now log in."
        );
    }
}
