package com.thehook.ias.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Identity & Access Service API",
                version = "1.0.0",
                description = "Centralized OAuth2/OIDC Authorization Server with RBAC and Multi-tenancy",
                contact = @Contact(
                        name = "IAS Team"
                )
        ),
        servers = {
                @Server(url = "http://localhost:9000", description = "Local Development")
        }
)
@SecurityScheme(
        name = "oauth2",
        type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "http://localhost:9000/oauth2/authorize",
                        tokenUrl = "http://localhost:9000/oauth2/token",
                        scopes = {
                                @OAuthScope(name = "openid", description = "OpenID Connect"),
                                @OAuthScope(name = "profile", description = "User profile"),
                                @OAuthScope(name = "email", description = "User email")
                        }
                )
        )
)
public class OpenApiConfig {
}
