# IAS Authorization Contract

This document defines the platform integration contract for the Identity & Access Service (IAS) authorization system. Resource servers and client applications must adhere to this contract when integrating with IAS.

**Version:** 1.0
**Last Updated:** 2026-02-01

---

## 1. Permission Naming Convention

All permissions follow the **colon-delimited** format:

```
<resource>:<action>
```

### Rules

| Rule | Example | Notes |
|------|---------|-------|
| Lowercase only | `org:read` | Never `Org:Read` or `ORG:READ` |
| Single colon separator | `member:invite` | Not `member.invite` or `member_invite` |
| Resource first, action second | `org:update` | Not `update:org` |
| Use singular nouns for resources | `member:read` | Not `members:read` |
| Use verb for action | `member:remove` | Not `member:removal` |

### Standard Actions

| Action | Meaning |
|--------|---------|
| `read` | View/retrieve resource |
| `create` | Create new resource |
| `update` | Modify existing resource |
| `delete` | Remove resource |
| `invite` | Send invitation |
| `remove` | Remove association |
| `assign` | Assign relationship |

### Examples

```
org:read           # View organization details
org:update         # Update organization settings
org:delete         # Delete organization
member:read        # View organization members
member:invite      # Invite new members
member:remove      # Remove members
member:role:assign # Assign roles to members
admin:roles:read   # View all roles (platform admin)
admin:roles:write  # Modify roles (platform admin)
```

---

## 2. System Roles

IAS provides three system-defined roles that cannot be deleted.

| Role ID | Name | Description |
|---------|------|-------------|
| `00000000-0000-0000-0000-000000000001` | PLATFORM_OWNER | Global super admin with all permissions |
| `00000000-0000-0000-0000-000000000002` | SELLER_ADMIN | Organization administrator |
| `00000000-0000-0000-0000-000000000003` | END_USER | Regular organization member |

### Role Hierarchy

```
PLATFORM_OWNER (all permissions)
    └── SELLER_ADMIN (org management)
            └── END_USER (basic access)
```

---

## 3. Permissions by Role

### PLATFORM_OWNER

Has **all permissions** including:

| Permission | Description |
|------------|-------------|
| `org:read` | View organization details |
| `org:update` | Update organization settings |
| `org:delete` | Delete organization |
| `member:read` | View organization members |
| `member:invite` | Invite new members |
| `member:remove` | Remove members |
| `member:role:assign` | Assign roles to members |
| `admin:roles:read` | View all roles |
| `admin:roles:write` | Create/modify roles |
| `admin:permissions:read` | View all permissions |
| `admin:permissions:write` | Create/modify permissions |
| `admin:users:read` | View all users |
| `admin:users:write` | Modify any user |
| `admin:orgs:read` | View all organizations |
| `admin:orgs:write` | Modify any organization |

### SELLER_ADMIN

| Permission | Description |
|------------|-------------|
| `org:read` | View organization details |
| `org:update` | Update organization settings |
| `member:read` | View organization members |
| `member:invite` | Invite new members |
| `member:remove` | Remove members |
| `member:role:assign` | Assign roles to members |

### END_USER

| Permission | Description |
|------------|-------------|
| `org:read` | View organization details |
| `member:read` | View organization members |

---

## 4. Authorization API Contract

### Endpoint

```
POST /authorize
```

### Authentication

Requires a valid JWT Bearer token. Any authenticated user can call this endpoint.

### Request

```json
{
  "userId": "uuid",
  "orgId": "uuid",
  "permissionKey": "string"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `userId` | UUID | Yes | The user to check permissions for |
| `orgId` | UUID | Yes | The organization context |
| `permissionKey` | String | Yes | Permission key (e.g., `org:read`) |

### Response

```json
{
  "allowed": boolean,
  "reason": string | null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | `true` if permission granted, `false` otherwise |
| `reason` | string | Reason for denial (null if allowed) |

### Example Request

```bash
curl -X POST http://localhost:9000/authorize \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "286db92c-3a99-4400-a39d-0abf92913498",
    "orgId": "aa7ef89c-703f-4a70-a060-3639410eb1da",
    "permissionKey": "org:read"
  }'
```

### Response Examples

**Allowed:**
```json
{
  "allowed": true,
  "reason": null
}
```

**Denied - Not a member:**
```json
{
  "allowed": false,
  "reason": "Not a member of this organization"
}
```

**Denied - Missing permission:**
```json
{
  "allowed": false,
  "reason": "Missing required permission: member:invite"
}
```

**Denied - User disabled:**
```json
{
  "allowed": false,
  "reason": "User is disabled"
}
```

---

## 5. Authorization Rules

### Rule 1: Self-Check Allowed

Any authenticated user can check permissions for **any userId**. This enables:
- Resource servers to validate permissions on behalf of users
- Backend services to pre-check authorization before operations

### Rule 2: PLATFORM_OWNER Bypass

Users with the `PLATFORM_OWNER` flag (`user.platformOwner = true`) automatically pass all permission checks regardless of organization membership.

### Rule 3: Membership Required

For non-platform-owners:
- User must have an **active** membership in the specified organization
- Membership must have at least one role with the requested permission

### Rule 4: Permission Inheritance

Permissions are checked via role membership:
```
User → Membership → Roles → Permissions
```

A user has a permission if **any** of their assigned roles contains that permission.

### Decision Flow

```
1. Is userId valid and enabled?
   └─ No → denied: "User not found" or "User is disabled"

2. Is user a PLATFORM_OWNER?
   └─ Yes → allowed

3. Is user an active member of orgId?
   └─ No → denied: "Not a member of this organization"

4. Does any role have the permissionKey?
   └─ Yes → allowed
   └─ No → denied: "Missing required permission: <key>"
```

---

## 6. Versioning & Evolution

### Adding New Permissions

1. **Create the permission** via admin API or migration:
   ```sql
   INSERT INTO permissions (id, key, description) VALUES
     (gen_random_uuid(), 'product:create', 'Create new products');
   ```

2. **Assign to roles** as needed:
   ```sql
   INSERT INTO role_permissions (role_id, permission_id)
   SELECT '00000000-0000-0000-0000-000000000002', id
   FROM permissions WHERE key = 'product:create';
   ```

3. **No breaking change**: Existing permission checks continue to work. New permission returns `false` until assigned.

### Adding New Roles

1. **Create role** via admin API:
   ```json
   POST /admin/roles
   {
     "name": "INVENTORY_MANAGER",
     "description": "Manages product inventory"
   }
   ```

2. **Assign permissions** to the role:
   ```json
   POST /admin/roles/{roleId}/permissions
   {
     "permissionIds": ["<product:create-id>", "<product:update-id>"]
   }
   ```

3. **Assign role** to memberships as needed.

### Deprecating Permissions

1. **Do not delete** permissions that may be in use
2. Add `[DEPRECATED]` prefix to description
3. Announce deprecation timeline (e.g., 6 months)
4. After timeline: remove from role assignments
5. Finally: delete the permission

### Backwards Compatibility Rules

| Change | Impact | Mitigation |
|--------|--------|------------|
| Add permission | None | New checks return `false` until role assigned |
| Add role | None | Must be explicitly assigned to members |
| Remove permission | Breaking | Follow deprecation process |
| Rename permission | Breaking | Create new, deprecate old |
| Change role permissions | Behavioral | Document and announce |

---

## 7. Integration Patterns

### Pattern A: Resource Server (Recommended)

```
Client App → Resource Server → IAS /authorize → Decision
```

1. Client sends request with JWT to Resource Server
2. Resource Server validates JWT signature via JWKS
3. Resource Server calls `POST /authorize` with user_id from JWT
4. Resource Server enforces decision

**Example (Spring Boot):**
```java
@GetMapping("/products/{id}")
public Product getProduct(@PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
    UUID userId = UUID.fromString(jwt.getClaimAsString("user_id"));
    UUID orgId = getOrgIdFromProduct(id);

    AuthorizeResponse response = iasClient.authorize(userId, orgId, "product:read");
    if (!response.allowed()) {
        throw new AccessDeniedException(response.reason());
    }

    return productRepository.findById(id);
}
```

### Pattern B: Gateway Authorization

```
Client App → API Gateway → IAS /authorize → Resource Server
```

Authorization check happens at the gateway level before routing.

### Pattern C: Embedded Check (Simple Apps)

For simple applications, embed permission check in business logic:

```java
if (!authorizeService.check(userId, orgId, "org:update")) {
    throw new ForbiddenException("Cannot update organization");
}
organization.setName(newName);
```

---

## 8. Error Handling

### HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Authorization check completed (check `allowed` field) |
| 400 | Invalid request (missing/malformed fields) |
| 401 | No valid JWT provided |
| 500 | Server error |

### Client Best Practices

1. **Always check `allowed` field** - HTTP 200 doesn't mean authorized
2. **Log denial reasons** for debugging
3. **Cache sparingly** - permissions can change
4. **Handle 401** by refreshing tokens

---

## Appendix: Permission Reference

| Permission Key | Assigned To | Description |
|----------------|-------------|-------------|
| `org:read` | END_USER, SELLER_ADMIN, PLATFORM_OWNER | View organization |
| `org:update` | SELLER_ADMIN, PLATFORM_OWNER | Update organization |
| `org:delete` | PLATFORM_OWNER | Delete organization |
| `member:read` | END_USER, SELLER_ADMIN, PLATFORM_OWNER | View members |
| `member:invite` | SELLER_ADMIN, PLATFORM_OWNER | Invite members |
| `member:remove` | SELLER_ADMIN, PLATFORM_OWNER | Remove members |
| `member:role:assign` | SELLER_ADMIN, PLATFORM_OWNER | Assign roles |
| `admin:roles:read` | PLATFORM_OWNER | View all roles |
| `admin:roles:write` | PLATFORM_OWNER | Manage roles |
| `admin:permissions:read` | PLATFORM_OWNER | View all permissions |
| `admin:permissions:write` | PLATFORM_OWNER | Manage permissions |
| `admin:users:read` | PLATFORM_OWNER | View all users |
| `admin:users:write` | PLATFORM_OWNER | Manage users |
| `admin:orgs:read` | PLATFORM_OWNER | View all orgs |
| `admin:orgs:write` | PLATFORM_OWNER | Manage orgs |
