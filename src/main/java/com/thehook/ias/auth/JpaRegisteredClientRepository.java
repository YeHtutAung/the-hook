package com.thehook.ias.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.*;

@Slf4j
@Repository
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    private static final String INSERT_CLIENT = """
            INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, client_secret,
                client_secret_expires_at, client_name, client_authentication_methods, authorization_grant_types,
                redirect_uris, post_logout_redirect_uris, scopes, client_settings, token_settings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_BY_ID = """
            SELECT * FROM oauth2_registered_client WHERE id = ?
            """;

    private static final String SELECT_BY_CLIENT_ID = """
            SELECT * FROM oauth2_registered_client WHERE client_id = ?
            """;

    @Override
    public void save(RegisteredClient registeredClient) {
        RegisteredClient existing = findById(registeredClient.getId());
        if (existing != null) {
            updateClient(registeredClient);
        } else {
            insertClient(registeredClient);
        }
    }

    private void insertClient(RegisteredClient client) {
        jdbcTemplate.update(INSERT_CLIENT,
                client.getId(),
                client.getClientId(),
                Timestamp.from(client.getClientIdIssuedAt()),
                client.getClientSecret(),
                client.getClientSecretExpiresAt() != null ?
                        Timestamp.from(client.getClientSecretExpiresAt()) : null,
                client.getClientName(),
                serializeSet(client.getClientAuthenticationMethods(), ClientAuthenticationMethod::getValue),
                serializeSet(client.getAuthorizationGrantTypes(), AuthorizationGrantType::getValue),
                serializeSet(client.getRedirectUris(), s -> s),
                serializeSet(client.getPostLogoutRedirectUris(), s -> s),
                serializeSet(client.getScopes(), s -> s),
                serializeSettings(client.getClientSettings()),
                serializeSettings(client.getTokenSettings())
        );
        log.info("Registered new OAuth2 client: {}", client.getClientId());
    }

    private void updateClient(RegisteredClient client) {
        jdbcTemplate.update("""
                UPDATE oauth2_registered_client SET
                    client_secret = ?, client_name = ?, client_authentication_methods = ?,
                    authorization_grant_types = ?, redirect_uris = ?, post_logout_redirect_uris = ?,
                    scopes = ?, client_settings = ?, token_settings = ?
                WHERE id = ?
                """,
                client.getClientSecret(),
                client.getClientName(),
                serializeSet(client.getClientAuthenticationMethods(), ClientAuthenticationMethod::getValue),
                serializeSet(client.getAuthorizationGrantTypes(), AuthorizationGrantType::getValue),
                serializeSet(client.getRedirectUris(), s -> s),
                serializeSet(client.getPostLogoutRedirectUris(), s -> s),
                serializeSet(client.getScopes(), s -> s),
                serializeSettings(client.getClientSettings()),
                serializeSettings(client.getTokenSettings()),
                client.getId()
        );
        log.info("Updated OAuth2 client: {}", client.getClientId());
    }

    @Override
    public RegisteredClient findById(String id) {
        List<RegisteredClient> clients = jdbcTemplate.query(SELECT_BY_ID, new RegisteredClientRowMapper(), id);
        return clients.isEmpty() ? null : clients.get(0);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        List<RegisteredClient> clients = jdbcTemplate.query(SELECT_BY_CLIENT_ID, new RegisteredClientRowMapper(), clientId);
        return clients.isEmpty() ? null : clients.get(0);
    }

    private <T> String serializeSet(Set<T> set, java.util.function.Function<T, String> mapper) {
        if (set == null || set.isEmpty()) return "";
        return String.join(",", set.stream().map(mapper).toList());
    }

    private String serializeSettings(Object settings) {
        try {
            return objectMapper.writeValueAsString(settings);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize settings", e);
        }
    }

    private class RegisteredClientRowMapper implements RowMapper<RegisteredClient> {
        @Override
        public RegisteredClient mapRow(ResultSet rs, int rowNum) throws SQLException {
            RegisteredClient.Builder builder = RegisteredClient.withId(rs.getString("id"))
                    .clientId(rs.getString("client_id"))
                    .clientIdIssuedAt(rs.getTimestamp("client_id_issued_at").toInstant())
                    .clientSecret(rs.getString("client_secret"))
                    .clientName(rs.getString("client_name"));

            Timestamp secretExpires = rs.getTimestamp("client_secret_expires_at");
            if (secretExpires != null) {
                builder.clientSecretExpiresAt(secretExpires.toInstant());
            }

            // Parse client authentication methods
            String authMethods = rs.getString("client_authentication_methods");
            if (StringUtils.hasText(authMethods)) {
                for (String method : authMethods.split(",")) {
                    builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method.trim()));
                }
            }

            // Parse authorization grant types
            String grantTypes = rs.getString("authorization_grant_types");
            if (StringUtils.hasText(grantTypes)) {
                for (String grantType : grantTypes.split(",")) {
                    builder.authorizationGrantType(new AuthorizationGrantType(grantType.trim()));
                }
            }

            // Parse redirect URIs
            String redirectUris = rs.getString("redirect_uris");
            if (StringUtils.hasText(redirectUris)) {
                for (String uri : redirectUris.split(",")) {
                    builder.redirectUri(uri.trim());
                }
            }

            // Parse post logout redirect URIs
            String postLogoutUris = rs.getString("post_logout_redirect_uris");
            if (StringUtils.hasText(postLogoutUris)) {
                for (String uri : postLogoutUris.split(",")) {
                    builder.postLogoutRedirectUri(uri.trim());
                }
            }

            // Parse scopes
            String scopes = rs.getString("scopes");
            if (StringUtils.hasText(scopes)) {
                for (String scope : scopes.split(",")) {
                    builder.scope(scope.trim());
                }
            }

            // Parse client settings
            String clientSettingsJson = rs.getString("client_settings");
            if (StringUtils.hasText(clientSettingsJson)) {
                try {
                    Map<String, Object> settingsMap = objectMapper.readValue(
                            clientSettingsJson, new TypeReference<>() {});
                    ClientSettings.Builder csBuilder = ClientSettings.builder();
                    if (settingsMap.containsKey("requireProofKey")) {
                        csBuilder.requireProofKey((Boolean) settingsMap.get("requireProofKey"));
                    }
                    if (settingsMap.containsKey("requireAuthorizationConsent")) {
                        csBuilder.requireAuthorizationConsent((Boolean) settingsMap.get("requireAuthorizationConsent"));
                    }
                    builder.clientSettings(csBuilder.build());
                } catch (Exception e) {
                    log.warn("Failed to parse client settings", e);
                }
            }

            // Parse token settings
            String tokenSettingsJson = rs.getString("token_settings");
            if (StringUtils.hasText(tokenSettingsJson)) {
                try {
                    Map<String, Object> settingsMap = objectMapper.readValue(
                            tokenSettingsJson, new TypeReference<>() {});
                    TokenSettings.Builder tsBuilder = TokenSettings.builder();
                    if (settingsMap.containsKey("accessTokenTimeToLive")) {
                        Object ttl = settingsMap.get("accessTokenTimeToLive");
                        if (ttl instanceof Number) {
                            tsBuilder.accessTokenTimeToLive(Duration.ofSeconds(((Number) ttl).longValue()));
                        }
                    }
                    if (settingsMap.containsKey("refreshTokenTimeToLive")) {
                        Object ttl = settingsMap.get("refreshTokenTimeToLive");
                        if (ttl instanceof Number) {
                            tsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(((Number) ttl).longValue()));
                        }
                    }
                    if (settingsMap.containsKey("reuseRefreshTokens")) {
                        tsBuilder.reuseRefreshTokens((Boolean) settingsMap.get("reuseRefreshTokens"));
                    }
                    builder.tokenSettings(tsBuilder.build());
                } catch (Exception e) {
                    log.warn("Failed to parse token settings", e);
                }
            }

            return builder.build();
        }
    }
}
