package com.thehook.ias.authorize.dto;

public record AuthorizeResponse(
        boolean allowed,
        String reason
) {
    public static AuthorizeResponse allow() {
        return new AuthorizeResponse(true, null);
    }

    public static AuthorizeResponse deny(String reason) {
        return new AuthorizeResponse(false, reason);
    }
}
