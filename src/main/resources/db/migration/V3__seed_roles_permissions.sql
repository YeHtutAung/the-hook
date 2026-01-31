-- V3: Seed default roles and permissions

-- System Roles
INSERT INTO roles (id, name, description, is_system_role) VALUES
    ('00000000-0000-0000-0000-000000000001', 'PLATFORM_OWNER', 'Global super admin with full system access', TRUE),
    ('00000000-0000-0000-0000-000000000002', 'SELLER_ADMIN', 'Organization administrator', TRUE),
    ('00000000-0000-0000-0000-000000000003', 'END_USER', 'Regular organization member', TRUE);

-- Default Permissions
INSERT INTO permissions (id, key, description) VALUES
    -- Organization permissions
    ('10000000-0000-0000-0000-000000000001', 'org:read', 'View organization details'),
    ('10000000-0000-0000-0000-000000000002', 'org:update', 'Update organization settings'),
    ('10000000-0000-0000-0000-000000000003', 'org:delete', 'Delete organization'),

    -- Member permissions
    ('10000000-0000-0000-0000-000000000010', 'member:read', 'View organization members'),
    ('10000000-0000-0000-0000-000000000011', 'member:invite', 'Invite new members'),
    ('10000000-0000-0000-0000-000000000012', 'member:remove', 'Remove members from organization'),
    ('10000000-0000-0000-0000-000000000013', 'member:role:assign', 'Assign roles to members'),

    -- Admin permissions (platform owner only)
    ('10000000-0000-0000-0000-000000000020', 'admin:roles:read', 'View all roles'),
    ('10000000-0000-0000-0000-000000000021', 'admin:roles:write', 'Create and modify roles'),
    ('10000000-0000-0000-0000-000000000022', 'admin:permissions:read', 'View all permissions'),
    ('10000000-0000-0000-0000-000000000023', 'admin:permissions:write', 'Create and modify permissions'),
    ('10000000-0000-0000-0000-000000000024', 'admin:users:read', 'View all users'),
    ('10000000-0000-0000-0000-000000000025', 'admin:users:write', 'Modify any user'),
    ('10000000-0000-0000-0000-000000000026', 'admin:orgs:read', 'View all organizations'),
    ('10000000-0000-0000-0000-000000000027', 'admin:orgs:write', 'Modify any organization');

-- PLATFORM_OWNER gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions;

-- SELLER_ADMIN permissions
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000001'), -- org:read
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'), -- org:update
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000010'), -- member:read
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000011'), -- member:invite
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000012'), -- member:remove
    ('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000013'); -- member:role:assign

-- END_USER permissions
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001'), -- org:read
    ('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000010'); -- member:read
