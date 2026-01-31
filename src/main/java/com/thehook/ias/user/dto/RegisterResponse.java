package com.thehook.ias.user.dto;

import java.util.UUID;

public record RegisterResponse(
        UUID userId,
        String email,
        String displayName,
        boolean emailVerified,
        String message,
        // For MVP: return verification token directly (in production, send via email)
        String verificationToken
) {
    public static RegisterResponse of(UUID userId, String email, String displayName, String verificationToken) {
        return new RegisterResponse(
                userId,
                email,
                displayName,
                false,
                "Registration successful. Please verify your email.",
                verificationToken
        );
    }
}
