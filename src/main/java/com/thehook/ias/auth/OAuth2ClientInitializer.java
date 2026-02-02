package com.thehook.ias.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

/**
 * Initializes demo OAuth2 clients for development/testing.
 * In production, clients should be registered through an admin API.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2ClientInitializer implements CommandLineRunner {

    private final RegisteredClientRepository clientRepository;

    @Override
    public void run(String... args) {
        // Demo public client (SPA/Mobile app using PKCE)
        if (clientRepository.findByClientId("demo-client") == null) {
            RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("demo-client")
                    .clientName("Demo Application")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:3000/callback")
                    .redirectUri("http://localhost:8080/callback")
                    .postLogoutRedirectUri("http://localhost:3000")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope(OidcScopes.EMAIL)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true) // Require PKCE
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .refreshTokenTimeToLive(Duration.ofDays(7))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            clientRepository.save(demoClient);
            log.info("Demo OAuth2 client registered: demo-client");
        }

        // Swagger UI client
        if (clientRepository.findByClientId("swagger-ui") == null) {
            RegisteredClient swaggerClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("swagger-ui")
                    .clientName("Swagger UI")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost:9000/swagger-ui/oauth2-redirect.html")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofHours(1))
                            .build())
                    .build();

            clientRepository.save(swaggerClient);
            log.info("Swagger UI OAuth2 client registered: swagger-ui");
        }

        // Pre-order Web App (React SPA using PKCE)
        if (clientRepository.findByClientId("preorder-web") == null) {
            RegisteredClient preorderWebClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("preorder-web")
                    .clientName("Pre-order Web Application")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client - no secret
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:3000/callback")
                    .postLogoutRedirectUri("http://localhost:3000")
                    .postLogoutRedirectUri("http://localhost:3000/")
                    .postLogoutRedirectUri("http://localhost:3000/owner/login")
                    .postLogoutRedirectUri("http://localhost:3000/seller/login")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope(OidcScopes.EMAIL)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true) // PKCE required
                            .requireAuthorizationConsent(false) // No consent screen
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .refreshTokenTimeToLive(Duration.ofDays(7))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            clientRepository.save(preorderWebClient);
            log.info("Pre-order Web OAuth2 client registered: preorder-web");
        }
    }
}
