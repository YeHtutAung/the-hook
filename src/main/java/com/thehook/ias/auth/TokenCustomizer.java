package com.thehook.ias.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;

/**
 * Customizes OAuth2/OIDC tokens with additional claims.
 *
 * Token strategy: Keep access tokens "thin" - include only essential claims.
 * Authorization decisions should be made via the /authorize endpoint.
 */
@Component
public class TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        // Access Token: Add audience for resource servers
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            // Use ArrayList to avoid Jackson serialization issues with immutable lists
            ArrayList<String> audiences = new ArrayList<>();
            audiences.add("preorder-api");
            context.getClaims().audience(audiences);
        }

        Authentication principal = context.getPrincipal();

        if (principal.getPrincipal() instanceof IasUserPrincipal userPrincipal) {
            String tokenType = context.getTokenType().getValue();

            // Use UUID as the subject instead of email.
            String subjectId = userPrincipal.getId().toString();
            context.getClaims().subject(subjectId);
            // Defensive: ensure sub is explicitly set to UUID.
            context.getClaims().claim("sub", subjectId);

            // Add user_id to all token types (access_token, id_token)
            context.getClaims().claim("user_id", subjectId);
            context.getClaims().claim("email", userPrincipal.getEmail());

            // ID Token: Add OIDC standard claims
            if ("id_token".equals(tokenType)) {
                context.getClaims().claim("name", userPrincipal.getDisplayName());
                context.getClaims().claim("email_verified", userPrincipal.isEmailVerified());
            }

            // Access Token: Add minimal claims for API authorization
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                // Platform owner flag for admin access
                if (userPrincipal.isPlatformOwner()) {
                    context.getClaims().claim("platform_owner", true);
                    ArrayList<String> roles = new ArrayList<>();
                    roles.add("PLATFORM_OWNER");
                    context.getClaims().claim("roles", roles);
                }
            }

            // Note: We intentionally do NOT embed permissions or org memberships in the token.
            // Clients should use the /authorize endpoint for permission checks.
            // This keeps tokens small and allows real-time permission updates.
        }
    }
}
