# Identity & Access Service (IAS)

A production-ready OAuth2/OIDC Authorization Server with centralized RBAC and multi-tenant organization membership.

## Overview

IAS is a standalone Spring Boot 3 service that provides:
- **Hosted Login** - OAuth2/OIDC Authorization Code + PKCE flow
- **Centralized RBAC** - Role-based access control with permissions
- **Multi-tenant Organizations** - Users can belong to multiple orgs with different roles
- **Authorization API** - Central permission checking endpoint for integrated apps

## Tech Stack

- Java 21
- Spring Boot 3.4.x
- Spring Security 6
- Spring Authorization Server 1.4.x
- Spring Data JPA (Hibernate)
- PostgreSQL
- Flyway Migrations
- Lombok
- OpenAPI/Swagger (springdoc-openapi)

## Quick Start

### Prerequisites

- Java 21+
- Docker & Docker Compose
- Maven 3.9+

### 1. Start PostgreSQL

```bash
docker-compose up -d
```

This starts PostgreSQL on port 5432 with:
- Database: `ias_db`
- Username: `ias_user`
- Password: `ias_password`

### 2. Run the Application

```bash
./mvnw spring-boot:run
```

The service starts at `http://localhost:9000`

### 3. Access Swagger UI

Open `http://localhost:9000/swagger-ui.html`

---

## Module 1: OAuth2/OIDC Authorization Server

### Architecture

IAS uses two SecurityFilterChains:

1. **Authorization Server Chain** (Order 1) - Handles OAuth2/OIDC protocol endpoints
   - `GET /oauth2/authorize` - Authorization endpoint
   - `POST /oauth2/token` - Token endpoint
   - `GET /oauth2/jwks` - JWK Set endpoint
   - `GET /.well-known/openid-configuration` - OIDC discovery

2. **Default Security Chain** (Order 2) - Handles all other requests
   - Form login for `/login`, `/register`, `/verify-email`
   - JWT resource server for API endpoints

### Pre-registered Demo Client (PKCE)

On startup, a public client is automatically registered:

| Property | Value |
|----------|-------|
| Client ID | `demo-client` |
| Client Secret | *none (public client)* |
| Grant Types | `authorization_code`, `refresh_token` |
| Redirect URIs | `http://localhost:3000/callback`, `http://localhost:8080/callback` |
| Scopes | `openid`, `profile`, `email` |
| PKCE | **Required** (S256) |

### Testing the OAuth2 Login Flow

#### Step 1: Create a User Account

Open your browser and navigate to:
```
http://localhost:9000/register
```

Fill in:
- Display Name: `Test User`
- Email: `test@example.com`
- Password: `password123`

Click "Create Account".

#### Step 2: Generate PKCE Challenge

For testing, generate a code verifier and challenge:

```bash
# Generate code_verifier (43-128 chars, URL-safe)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
echo "Code Verifier: $CODE_VERIFIER"

# Generate code_challenge (S256)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '/+' '_-')
echo "Code Challenge: $CODE_CHALLENGE"
```

Or use these pre-computed test values:
```
code_verifier:  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

#### Step 3: Start Authorization Flow

Open in your browser (replace `CODE_CHALLENGE` with your value):

```
http://localhost:9000/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=xyz123
```

You'll be redirected to the login page. Enter your credentials:
- Email: `test@example.com`
- Password: `password123`

After login, you'll be redirected to:
```
http://localhost:3000/callback?code=AUTHORIZATION_CODE&state=xyz123
```

Copy the `code` parameter value.

#### Step 4: Exchange Code for Tokens

```bash
# Replace AUTHORIZATION_CODE and CODE_VERIFIER with your values
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=demo-client" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code=AUTHORIZATION_CODE" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

Response:
```json
{
  "access_token": "eyJraWQiOi...",
  "refresh_token": "abc123...",
  "scope": "openid profile email",
  "id_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 899
}
```

#### Step 5: Verify the Access Token

Decode the JWT at [jwt.io](https://jwt.io) or use:

```bash
# Extract payload (middle part of JWT)
echo "ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

Expected claims:
```json
{
  "sub": "test@example.com",
  "aud": "demo-client",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "test@example.com",
  "iss": "http://localhost:9000",
  "exp": 1234567890,
  "iat": 1234567890
}
```

#### Step 6: Use Refresh Token

```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=demo-client" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

#### Step 7: Access Protected API

```bash
curl http://localhost:9000/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "test@example.com",
  "displayName": "Test User",
  "emailVerified": false,
  "platformOwner": false,
  "createdAt": "2024-01-15T10:30:00Z"
}
```

### OIDC Discovery

```bash
curl http://localhost:9000/.well-known/openid-configuration | jq .
```

Response:
```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
  "token_endpoint": "http://localhost:9000/oauth2/token",
  "jwks_uri": "http://localhost:9000/oauth2/jwks",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"]
}
```

### JWK Set (for token verification)

```bash
curl http://localhost:9000/oauth2/jwks | jq .
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "ias-key-1",
      "n": "..."
    }
  ]
}
```

### Registering a New OAuth2 Client

#### Option 1: SQL Insert

```sql
INSERT INTO oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    redirect_uris, scopes, client_settings, token_settings
) VALUES (
    gen_random_uuid(),
    'my-spa-app',
    NOW(),
    NULL,  -- NULL for public clients
    'My SPA Application',
    'none',  -- Public client
    'authorization_code,refresh_token',
    'https://myapp.com/callback,https://myapp.com/silent-refresh',
    'openid,profile,email',
    '{"requireProofKey":true,"requireAuthorizationConsent":false}',
    '{"accessTokenTimeToLive":900,"refreshTokenTimeToLive":604800,"reuseRefreshTokens":false}'
);
```

#### Option 2: Confidential Client (with secret)

```sql
-- First, generate a BCrypt hash of your secret
-- You can use: echo -n 'my-secret' | htpasswd -bnBC 10 "" - | tr -d ':\n'

INSERT INTO oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    redirect_uris, scopes, client_settings, token_settings
) VALUES (
    gen_random_uuid(),
    'my-backend-app',
    NOW(),
    '$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW',  -- BCrypt of 'secret'
    'My Backend Application',
    'client_secret_basic',  -- or 'client_secret_post'
    'authorization_code,refresh_token,client_credentials',
    'https://myapp.com/callback',
    'openid,profile,email',
    '{"requireProofKey":false,"requireAuthorizationConsent":true}',
    '{"accessTokenTimeToLive":3600,"refreshTokenTimeToLive":86400,"reuseRefreshTokens":false}'
);
```

---

## Database Schema

### Core Tables (V1)

| Table | Description |
|-------|-------------|
| users | User accounts |
| organizations | Tenant organizations |
| memberships | User-Organization links |
| roles | Role definitions |
| permissions | Permission keys |
| role_permissions | Role-Permission mapping |
| membership_roles | Roles assigned per membership |
| invitations | Pending org invitations |
| email_verifications | Email verification tokens |
| audit_logs | Audit trail for security events |

### OAuth2 Tables (V2)

| Table | Description |
|-------|-------------|
| oauth2_registered_client | Registered OAuth2 clients |
| oauth2_authorization | Active authorizations (tokens) |
| oauth2_authorization_consent | User consent records |

---

## API Endpoints

### User Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/me` | Get current user profile |
| GET | `/me/memberships` | Get user's org memberships |

### Organization Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/orgs` | Create organization |
| POST | `/orgs/{orgId}/members/invite` | Invite member |
| POST | `/orgs/{orgId}/members/accept` | Accept invitation |

### Authorization Endpoint

| Method | Path | Description |
|--------|------|-------------|
| POST | `/authorize` | Check permission |

**Request:**
```json
{
  "userId": "uuid",
  "orgId": "uuid",
  "permissionKey": "resource:action"
}
```

**Response:**
```json
{
  "allowed": true,
  "reason": null
}
```

### Admin Endpoints (PLATFORM_OWNER only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/roles` | List all roles |
| POST | `/admin/roles` | Create role |
| POST | `/admin/roles/{id}/permissions` | Assign permissions |
| GET | `/admin/permissions` | List all permissions |
| POST | `/admin/permissions` | Create permission |

---

## Token Strategy

### Access Token Claims

Tokens are intentionally "thin" and include:
- `iss` - Issuer URI
- `sub` - User email (username)
- `aud` - Client ID
- `exp` - Expiration
- `iat` - Issued at
- `user_id` - User UUID
- `email` - User email
- `platform_owner` - Boolean (only if true)

**Note:** Permissions are NOT embedded in tokens. Use the `/authorize` endpoint for permission checks.

### Token Lifetimes (demo-client)

| Token Type | Lifetime |
|------------|----------|
| Access Token | 15 minutes |
| Refresh Token | 7 days |

---

## Development

### Running Tests

```bash
./mvnw test
```

### Project Structure

```
src/main/java/com/thehook/ias/
├── IasApplication.java
├── admin/          # Admin endpoints
├── auth/           # OAuth2/Auth configuration
│   ├── AuthController.java         # Login/register pages
│   ├── IasUserDetailsService.java  # User authentication
│   ├── IasUserPrincipal.java       # User principal
│   ├── JpaRegisteredClientRepository.java  # Client storage
│   ├── OAuth2ClientInitializer.java # Demo client setup
│   └── TokenCustomizer.java        # JWT claims customization
├── authorize/      # Authorization API
├── common/         # Shared entities, exceptions, audit
├── config/         # Security, OpenAPI config
│   └── SecurityConfig.java         # Two filter chains
├── org/            # Organizations, memberships, invitations
├── rbac/           # Roles and permissions
└── user/           # User management

src/main/resources/
├── application.yml
├── db/migration/
│   ├── V1__create_core_tables.sql
│   ├── V2__create_oauth2_tables.sql
│   └── V3__seed_roles_permissions.sql
└── templates/
    ├── login.html
    └── register.html
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/ias_db` | Database URL |
| `SPRING_DATASOURCE_USERNAME` | `ias_user` | Database username |
| `SPRING_DATASOURCE_PASSWORD` | `ias_password` | Database password |
| `IAS_ISSUER_URI` | `http://localhost:9000` | OAuth2 issuer URI |

### Production Recommendations

1. Use externalized RSA key pairs (not generated on startup)
2. Configure proper CORS settings
3. Enable HTTPS
4. Use proper secrets management
5. Configure rate limiting
6. Set up monitoring and alerting

---

## Troubleshooting

### Common Issues

**1. "Invalid redirect_uri"**
- Ensure the redirect_uri exactly matches what's registered in the database
- Check for trailing slashes

**2. "invalid_grant" on token exchange**
- Authorization codes expire quickly (5 minutes)
- Codes can only be used once
- Ensure code_verifier matches the original code_challenge

**3. "Login redirects back to login"**
- Check if user account is enabled
- Verify password is correct
- Check logs for authentication failures

**4. JWK endpoint returns empty keys**
- Keys are generated on startup; restart if needed
- In production, use persistent key configuration

---

## License

MIT
