# IAS Integration & Validation Guide

## 1. Step-by-Step Manual Verification: Hosted Login with Authorization Code + PKCE

### Prerequisites
- IAS running at `http://localhost:9000`
- A registered user (create via `POST /auth/register`)
- Browser for login flow
- Terminal for curl commands

### Step 1: Register a Test User

```bash
curl -X POST http://localhost:9000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "Password123!",
    "displayName": "Test User"
  }'
```

**Expected Response (201 Created):**
```json
{
  "userId": "<uuid>",
  "email": "testuser@example.com",
  "verificationToken": "<token>",
  "message": "Registration successful. Please verify your email."
}
```

### Step 2: Verify Email

```bash
curl -X POST http://localhost:9000/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<verificationToken-from-step-1>"}'
```

**Expected Response (200 OK):**
```json
{
  "email": "testuser@example.com",
  "emailVerified": true,
  "message": "Email verified successfully"
}
```

### Step 3: Generate PKCE Code Verifier and Challenge

```bash
# Generate code_verifier (43-128 chars, URL-safe)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-' | cut -c1-43)
echo "code_verifier: $CODE_VERIFIER"

# Generate code_challenge (SHA256 hash, base64url encoded)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
echo "code_challenge: $CODE_CHALLENGE"

# Generate state (CSRF protection)
STATE=$(openssl rand -hex 16)
echo "state: $STATE"
```

**Example Values:**
```
code_verifier:  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
state:          abc123xyz789
```

### Step 4: Build Authorization URL

**URL Format:**
```
http://localhost:9000/oauth2/authorize
  ?response_type=code
  &client_id=demo-client
  &redirect_uri=http://localhost:3000/callback
  &scope=openid profile email
  &state=<state>
  &code_challenge=<code_challenge>
  &code_challenge_method=S256
```

**Complete Example URL:**
```
http://localhost:9000/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=abc123xyz789&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

### Step 5: Open in Browser & Login

1. Open the authorization URL in browser
2. You will be redirected to `/login`
3. Enter credentials: `testuser@example.com` / `Password123!`
4. After successful login, browser redirects to:
   ```
   http://localhost:3000/callback?code=<authorization_code>&state=abc123xyz789
   ```

**Note:** Since `localhost:3000` isn't running, copy the `code` parameter from the browser URL bar.

### Step 6: Exchange Authorization Code for Tokens

```bash
# Replace <authorization_code> with actual code from Step 5
# Replace <code_verifier> with value from Step 3

curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=demo-client" \
  -d "code_verifier=<code_verifier>"
```

**Expected Response (200 OK):**
```json
{
  "access_token": "eyJraWQiOi...",
  "refresh_token": "eyJraWQiOi...",
  "scope": "openid profile email",
  "id_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 899
}
```

### Step 7: Call Protected APIs

```bash
# Store the access token
ACCESS_TOKEN="<access_token_from_step_6>"

# Call /me endpoint
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9000/me

# Call /me/memberships
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9000/me/memberships
```

---

## 2. Endpoint Documentation

### `/.well-known/openid-configuration`
**Method:** GET
**Auth:** None (Public)
**Response:**
```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
  "token_endpoint": "http://localhost:9000/oauth2/token",
  "jwks_uri": "http://localhost:9000/oauth2/jwks",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "..."],
  "code_challenge_methods_supported": ["S256"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

### `/oauth2/jwks`
**Method:** GET
**Auth:** None (Public)
**Response:**
```json
{
  "keys": [{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "<key-id>",
    "n": "<modulus>"
  }]
}
```

### `/login`
**Method:** GET
**Auth:** None (Public)
**Content-Type:** text/html
**Description:** Thymeleaf-rendered login page for hosted login flow

### `/oauth2/authorize`
**Method:** GET
**Auth:** Session-based (redirects to /login if unauthenticated)
**Required Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| response_type | Yes | Must be `code` |
| client_id | Yes | Registered client ID |
| redirect_uri | Yes | Must match registered URI |
| scope | Yes | Space-separated scopes (include `openid`) |
| state | Recommended | CSRF protection token |
| code_challenge | Yes (PKCE) | Base64url-encoded SHA256 of verifier |
| code_challenge_method | Yes (PKCE) | Must be `S256` |

### `/oauth2/token`
**Method:** POST
**Auth:** None for public clients (PKCE), client credentials for confidential
**Content-Type:** application/x-www-form-urlencoded
**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| grant_type | Yes | `authorization_code` or `refresh_token` |
| code | Yes* | Authorization code (for auth_code grant) |
| redirect_uri | Yes* | Must match authorize request |
| client_id | Yes | Registered client ID |
| code_verifier | Yes (PKCE) | Original PKCE verifier |
| refresh_token | Yes* | For refresh_token grant |

---

## 3. OAuth Client Registration

### Storage Location
- **Database Table:** `oauth2_registered_client`
- **Repository:** `JpaRegisteredClientRepository.java`
- **Initialization:** `OAuth2ClientInitializer.java` (runs on startup)

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| client_id | String | Public client identifier |
| client_name | String | Display name |
| client_authentication_methods | String | `none` for public, `client_secret_basic` for confidential |
| authorization_grant_types | String | Comma-separated: `authorization_code,refresh_token` |
| redirect_uris | String | Comma-separated allowed redirect URIs |
| scopes | String | Comma-separated: `openid,profile,email` |
| client_settings | JSON | `{"requireProofKey": true}` for PKCE |
| token_settings | JSON | TTL configuration |

### Example: Register a Public Client (PKCE)

**Option A: Add to `OAuth2ClientInitializer.java`**
```java
RegisteredClient myApp = RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("my-spa-app")
    .clientName("My SPA Application")
    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    .redirectUri("http://localhost:4200/callback")
    .redirectUri("https://myapp.com/callback")
    .scope(OidcScopes.OPENID)
    .scope(OidcScopes.PROFILE)
    .scope(OidcScopes.EMAIL)
    .clientSettings(ClientSettings.builder()
        .requireProofKey(true)
        .requireAuthorizationConsent(false)
        .build())
    .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(15))
        .refreshTokenTimeToLive(Duration.ofDays(7))
        .reuseRefreshTokens(false)
        .build())
    .build();
clientRepository.save(myApp);
```

**Option B: Direct SQL (Flyway migration)**
```sql
INSERT INTO oauth2_registered_client (
  id, client_id, client_id_issued_at, client_name,
  client_authentication_methods, authorization_grant_types,
  redirect_uris, scopes, client_settings, token_settings
) VALUES (
  gen_random_uuid(),
  'my-spa-app',
  NOW(),
  'My SPA Application',
  'none',
  'authorization_code,refresh_token',
  'http://localhost:4200/callback,https://myapp.com/callback',
  'openid,profile,email',
  '{"requireProofKey":true,"requireAuthorizationConsent":false}',
  '{"accessTokenTimeToLive":900,"refreshTokenTimeToLive":604800,"reuseRefreshTokens":false}'
);
```

---

## 4. Copy-Paste curl Commands

### Exchange Authorization Code for Tokens
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=demo-client" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

### GET /me (Current User Profile)
```bash
curl -X GET http://localhost:9000/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### GET /me/memberships (User's Organizations)
```bash
curl -X GET http://localhost:9000/me/memberships \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### POST /authorize (Check Permission)
```bash
curl -X POST http://localhost:9000/authorize \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "USER_UUID",
    "orgId": "ORG_UUID",
    "permissionKey": "org:read"
  }'
```

**Expected Response:**
```json
{
  "allowed": true,
  "reason": "Permission granted via role membership",
  "userId": "...",
  "orgId": "...",
  "permissionKey": "org:read",
  "userRoles": ["END_USER"]
}
```

---

## 5. Security Configuration Review

### Filter Chain Ordering: CORRECT

| Order | Chain | Purpose |
|-------|-------|---------|
| 1 | `authorizationServerSecurityFilterChain` | OAuth2/OIDC endpoints (`/oauth2/**`, `/.well-known/**`) |
| 2 | `defaultSecurityFilterChain` | All other endpoints (APIs, login pages) |

### API Protection: CORRECT

- **JWT Resource Server** is configured on both chains via `.oauth2ResourceServer(oauth2 -> oauth2.jwt(...))`
- All API endpoints (`/me/**`, `/orgs/**`, `/authorize`, `/admin/**`) require authentication
- Method-level security enabled via `@EnableMethodSecurity` and `@PreAuthorize` annotations

### OAuth Endpoints: NOT BLOCKED

- OAuth endpoints are handled by Chain #1 (Order 1) before Chain #2
- Chain #1 applies Spring Authorization Server default security
- Public OAuth endpoints (`/.well-known/*`, `/oauth2/jwks`) are accessible without authentication

### Public Endpoints Verified:
- `/login`, `/register`, `/verify-email` - Form pages
- `/auth/register`, `/auth/verify`, `/auth/resend-verification` - REST APIs
- `/swagger-ui/**`, `/api-docs/**` - API documentation
- `/actuator/health` - Health check

### CSRF Configuration:
- Enabled for form login (session-based)
- Disabled for API endpoints (they use JWT)

---

## 6. Production-Readiness Items (NOT YET IMPLEMENTED)

### Security
- [ ] **HTTPS enforcement** - All production traffic must use TLS
- [ ] **Externalized RSA keys** - Keys regenerate on restart; use external key store
- [ ] **Key rotation** - Implement JWKS key rotation with `kid` versioning
- [ ] **Secure cookie settings** - Set `Secure`, `HttpOnly`, `SameSite=Strict`

### Rate Limiting & Abuse Prevention
- [ ] **Rate limiting** - `/auth/register`, `/auth/verify`, `/oauth2/token`
- [ ] **Brute force protection** - Account lockout after failed login attempts
- [ ] **CAPTCHA** - On registration and login after failures

### Token Management
- [ ] **Refresh token rotation** - Currently `reuseRefreshTokens=false` but no rotation
- [ ] **Token revocation on password change** - Invalidate all tokens
- [ ] **Shorter access token TTL** - Consider 5 minutes for high-security

### Observability
- [ ] **Structured logging** - JSON format for log aggregation
- [ ] **Metrics** - Micrometer/Prometheus for auth success/failure rates
- [ ] **Distributed tracing** - Correlation IDs across services
- [ ] **Audit log persistence** - Currently in-DB; consider external audit store

### High Availability
- [ ] **Stateless sessions** - Current session handling needs review for multi-instance
- [ ] **Redis session store** - For horizontal scaling
- [ ] **Database connection pooling tuning** - HikariCP settings for production load

### Configuration
- [ ] **Externalized secrets** - Database credentials, etc. via environment/vault
- [ ] **Profile-based configuration** - `application-prod.yml`
- [ ] **CORS configuration** - Restrict origins in production

### Compliance
- [ ] **Password policy enforcement** - Configurable rules
- [ ] **Email verification expiry** - Currently 24h, may need adjustment
- [ ] **GDPR considerations** - User data export/deletion endpoints

---

## Assumptions Made

1. **demo-client** is the pre-registered public OAuth2 client with PKCE support
2. Redirect URI `http://localhost:3000/callback` is registered for demo-client
3. User must be email-verified to log in successfully
4. The `/authorize` endpoint requires `PLATFORM_OWNER` role or `admin:authorize` permission
5. RSA keys are generated on each startup (not persisted)

---

## Quick Validation Checklist

| Check | Command | Expected |
|-------|---------|----------|
| OIDC Discovery | `curl http://localhost:9000/.well-known/openid-configuration` | JSON with endpoints |
| JWKS | `curl http://localhost:9000/oauth2/jwks` | JSON with RSA key |
| Login Page | `curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/login` | 200 |
| Protected API (no token) | `curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/me` | 401 |
| Swagger UI | Open `http://localhost:9000/swagger-ui.html` | Swagger page loads |
