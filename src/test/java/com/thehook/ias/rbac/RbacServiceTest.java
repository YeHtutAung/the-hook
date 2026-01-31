package com.thehook.ias.rbac;

import com.thehook.ias.authorize.AuthorizeCacheService;
import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.org.Membership;
import com.thehook.ias.org.MembershipRepository;
import com.thehook.ias.org.MembershipStatus;
import com.thehook.ias.org.Organization;
import com.thehook.ias.rbac.dto.*;
import com.thehook.ias.user.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RbacServiceTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private MembershipRepository membershipRepository;

    @Mock
    private AuditService auditService;

    @Mock
    private AuthorizeCacheService authorizeCacheService;

    @InjectMocks
    private RbacService rbacService;

    private Role testRole;
    private Permission testPermission;
    private UUID testRoleId;
    private UUID testPermissionId;
    private UUID actorId;
    private String ipAddress;

    @BeforeEach
    void setUp() {
        testRoleId = UUID.randomUUID();
        testPermissionId = UUID.randomUUID();
        actorId = UUID.randomUUID();
        ipAddress = "127.0.0.1";

        testPermission = Permission.builder()
                .key("user:read")
                .description("Read user data")
                .build();
        testPermission.setId(testPermissionId);

        testRole = Role.builder()
                .name("ADMIN")
                .description("Administrator role")
                .systemRole(false)
                .permissions(new HashSet<>(Set.of(testPermission)))
                .build();
        testRole.setId(testRoleId);
        testRole.setCreatedAt(Instant.now());
    }

    @Nested
    @DisplayName("Role Operations")
    class RoleOperationsTests {

        @Test
        @DisplayName("should get all roles")
        void shouldGetAllRoles() {
            Role role2 = Role.builder()
                    .name("USER")
                    .description("User role")
                    .systemRole(false)
                    .permissions(new HashSet<>())
                    .build();
            role2.setId(UUID.randomUUID());

            when(roleRepository.findAllWithPermissions()).thenReturn(List.of(testRole, role2));

            List<RoleDto> result = rbacService.getAllRoles();

            assertThat(result).hasSize(2);
            assertThat(result.get(0).name()).isEqualTo("ADMIN");
            assertThat(result.get(1).name()).isEqualTo("USER");
        }

        @Test
        @DisplayName("should get role by id")
        void shouldGetRoleById() {
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));

            RoleDto result = rbacService.getRoleById(testRoleId);

            assertThat(result.id()).isEqualTo(testRoleId);
            assertThat(result.name()).isEqualTo("ADMIN");
            assertThat(result.permissions()).contains("user:read");
        }

        @Test
        @DisplayName("should throw not found when role does not exist")
        void shouldThrowNotFoundWhenRoleDoesNotExist() {
            UUID unknownId = UUID.randomUUID();
            when(roleRepository.findByIdWithPermissions(unknownId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> rbacService.getRoleById(unknownId))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }

        @Test
        @DisplayName("should get role by name")
        void shouldGetRoleByName() {
            when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(testRole));

            Role result = rbacService.getRoleByName("ADMIN");

            assertThat(result.getName()).isEqualTo("ADMIN");
        }

        @Test
        @DisplayName("should throw not found when role name does not exist")
        void shouldThrowNotFoundWhenRoleNameDoesNotExist() {
            when(roleRepository.findByName("UNKNOWN")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> rbacService.getRoleByName("UNKNOWN"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }

        @Test
        @DisplayName("should create role successfully")
        void shouldCreateRole() {
            CreateRoleRequest request = new CreateRoleRequest("NEW_ROLE", "New role description");

            when(roleRepository.existsByName("NEW_ROLE")).thenReturn(false);
            when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
                Role role = invocation.getArgument(0);
                role.setId(UUID.randomUUID());
                return role;
            });

            RoleDto result = rbacService.createRole(request);

            assertThat(result.name()).isEqualTo("NEW_ROLE");
            assertThat(result.description()).isEqualTo("New role description");
            assertThat(result.systemRole()).isFalse();
            verify(roleRepository).save(any(Role.class));
        }

        @Test
        @DisplayName("should throw conflict when role name already exists")
        void shouldThrowConflictWhenRoleExists() {
            CreateRoleRequest request = new CreateRoleRequest("ADMIN", "Description");

            when(roleRepository.existsByName("ADMIN")).thenReturn(true);

            assertThatThrownBy(() -> rbacService.createRole(request))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("Role already exists");
                    });

            verify(roleRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Assign Permissions")
    class AssignPermissionsTests {

        @Test
        @DisplayName("should assign permissions to role")
        void shouldAssignPermissions() {
            Permission newPermission = Permission.builder()
                    .key("user:write")
                    .description("Write user data")
                    .build();
            newPermission.setId(UUID.randomUUID());

            Set<UUID> permissionIds = Set.of(newPermission.getId());

            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds)).thenReturn(List.of(newPermission));
            when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

            RoleDto result = rbacService.assignPermissions(testRoleId, permissionIds);

            assertThat(result.permissions()).contains("user:read", "user:write");
            verify(roleRepository).save(testRole);
        }

        @Test
        @DisplayName("should throw forbidden when modifying system role")
        void shouldThrowForbiddenForSystemRole() {
            testRole.setSystemRole(true);
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> rbacService.assignPermissions(testRoleId, Set.of(UUID.randomUUID())))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                        assertThat(iasEx.getMessage()).contains("system role");
                    });

            verify(roleRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw bad request when permission IDs are invalid")
        void shouldThrowBadRequestWhenPermissionIdsInvalid() {
            UUID validId = UUID.randomUUID();
            UUID invalidId = UUID.randomUUID();
            Set<UUID> permissionIds = Set.of(validId, invalidId);

            Permission validPermission = Permission.builder()
                    .key("valid:perm")
                    .build();
            validPermission.setId(validId);

            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds)).thenReturn(List.of(validPermission));

            assertThatThrownBy(() -> rbacService.assignPermissions(testRoleId, permissionIds))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("invalid");
                    });
        }

        @Test
        @DisplayName("should throw not found when role does not exist")
        void shouldThrowNotFoundWhenRoleNotExists() {
            UUID unknownRoleId = UUID.randomUUID();
            when(roleRepository.findByIdWithPermissions(unknownRoleId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> rbacService.assignPermissions(unknownRoleId, Set.of(UUID.randomUUID())))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }
    }

    @Nested
    @DisplayName("Permission Operations")
    class PermissionOperationsTests {

        @Test
        @DisplayName("should get all permissions")
        void shouldGetAllPermissions() {
            Permission perm2 = Permission.builder()
                    .key("user:write")
                    .description("Write user data")
                    .build();
            perm2.setId(UUID.randomUUID());

            when(permissionRepository.findAllOrderByKey()).thenReturn(List.of(testPermission, perm2));

            List<PermissionDto> result = rbacService.getAllPermissions();

            assertThat(result).hasSize(2);
            assertThat(result.get(0).key()).isEqualTo("user:read");
            assertThat(result.get(1).key()).isEqualTo("user:write");
        }

        @Test
        @DisplayName("should get permission by id")
        void shouldGetPermissionById() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));

            PermissionDto result = rbacService.getPermissionById(testPermissionId);

            assertThat(result.id()).isEqualTo(testPermissionId);
            assertThat(result.key()).isEqualTo("user:read");
            assertThat(result.description()).isEqualTo("Read user data");
        }

        @Test
        @DisplayName("should throw not found when permission does not exist")
        void shouldThrowNotFoundWhenPermissionDoesNotExist() {
            UUID unknownId = UUID.randomUUID();
            when(permissionRepository.findById(unknownId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> rbacService.getPermissionById(unknownId))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }

        @Test
        @DisplayName("should create permission successfully")
        void shouldCreatePermission() {
            CreatePermissionRequest request = new CreatePermissionRequest("order:create", "Create orders");

            when(permissionRepository.existsByKey("order:create")).thenReturn(false);
            when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> {
                Permission perm = invocation.getArgument(0);
                perm.setId(UUID.randomUUID());
                return perm;
            });

            PermissionDto result = rbacService.createPermission(request);

            assertThat(result.key()).isEqualTo("order:create");
            assertThat(result.description()).isEqualTo("Create orders");
            verify(permissionRepository).save(any(Permission.class));
        }

        @Test
        @DisplayName("should throw conflict when permission key already exists")
        void shouldThrowConflictWhenPermissionExists() {
            CreatePermissionRequest request = new CreatePermissionRequest("user:read", "Read users");

            when(permissionRepository.existsByKey("user:read")).thenReturn(true);

            assertThatThrownBy(() -> rbacService.createPermission(request))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("Permission already exists");
                    });

            verify(permissionRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Update Role Operations")
    class UpdateRoleTests {

        @Test
        @DisplayName("should update role description")
        void shouldUpdateRoleDescription() {
            UpdateRoleRequest request = new UpdateRoleRequest("Updated description");
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.save(any(Role.class))).thenAnswer(inv -> inv.getArgument(0));

            RoleDto result = rbacService.updateRole(testRoleId, request, actorId, ipAddress);

            assertThat(result.description()).isEqualTo("Updated description");
            verify(auditService).logRoleUpdated(eq(testRoleId), eq("ADMIN"), eq(actorId), any(), eq(ipAddress));
        }

        @Test
        @DisplayName("should throw forbidden when updating system role")
        void shouldThrowForbiddenWhenUpdatingSystemRole() {
            testRole.setSystemRole(true);
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> rbacService.updateRole(testRoleId, new UpdateRoleRequest("New desc"), actorId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> assertThat(((IasException) ex).getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        }
    }

    @Nested
    @DisplayName("Delete Role Operations")
    class DeleteRoleTests {

        @Test
        @DisplayName("should delete role successfully")
        void shouldDeleteRole() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(membershipRepository.existsByRoleId(testRoleId)).thenReturn(false);

            rbacService.deleteRole(testRoleId, actorId, ipAddress);

            verify(roleRepository).delete(testRole);
            verify(auditService).logRoleDeleted(testRoleId, "ADMIN", actorId, ipAddress);
        }

        @Test
        @DisplayName("should throw forbidden when deleting system role")
        void shouldThrowForbiddenWhenDeletingSystemRole() {
            testRole.setSystemRole(true);
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> rbacService.deleteRole(testRoleId, actorId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> assertThat(((IasException) ex).getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        }

        @Test
        @DisplayName("should throw conflict when role is assigned to members")
        void shouldThrowConflictWhenRoleInUse() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(membershipRepository.existsByRoleId(testRoleId)).thenReturn(true);

            assertThatThrownBy(() -> rbacService.deleteRole(testRoleId, actorId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("assigned to members");
                    });
        }
    }

    @Nested
    @DisplayName("Remove Permissions Operations")
    class RemovePermissionsTests {

        @Test
        @DisplayName("should remove permissions from role")
        void shouldRemovePermissions() {
            Set<UUID> permissionIds = Set.of(testPermissionId);
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.save(any(Role.class))).thenAnswer(inv -> inv.getArgument(0));

            RoleDto result = rbacService.removePermissions(testRoleId, permissionIds, actorId, ipAddress);

            assertThat(result.permissions()).doesNotContain("user:read");
            verify(auditService).logPermissionsRemovedFromRole(eq(testRoleId), eq("ADMIN"), any(), eq(actorId), eq(ipAddress));
        }
    }

    @Nested
    @DisplayName("Update Permission Operations")
    class UpdatePermissionTests {

        @Test
        @DisplayName("should update permission description")
        void shouldUpdatePermissionDescription() {
            UpdatePermissionRequest request = new UpdatePermissionRequest("Updated permission description");
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(permissionRepository.save(any(Permission.class))).thenAnswer(inv -> inv.getArgument(0));

            PermissionDto result = rbacService.updatePermission(testPermissionId, request, actorId, ipAddress);

            assertThat(result.description()).isEqualTo("Updated permission description");
            verify(auditService).logPermissionUpdated(eq(testPermissionId), eq("user:read"), eq(actorId), any(), eq(ipAddress));
        }
    }

    @Nested
    @DisplayName("Delete Permission Operations")
    class DeletePermissionTests {

        @Test
        @DisplayName("should delete permission successfully")
        void shouldDeletePermission() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(roleRepository.existsByPermissionId(testPermissionId)).thenReturn(false);

            rbacService.deletePermission(testPermissionId, actorId, ipAddress);

            verify(permissionRepository).delete(testPermission);
            verify(auditService).logPermissionDeleted(testPermissionId, "user:read", actorId, ipAddress);
        }

        @Test
        @DisplayName("should throw conflict when permission is assigned to roles")
        void shouldThrowConflictWhenPermissionInUse() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(roleRepository.existsByPermissionId(testPermissionId)).thenReturn(true);

            assertThatThrownBy(() -> rbacService.deletePermission(testPermissionId, actorId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("assigned to roles");
                    });
        }
    }

    @Nested
    @DisplayName("Membership Role Operations")
    class MembershipRoleTests {

        private Membership testMembership;
        private UUID membershipId;
        private UUID orgId;

        @BeforeEach
        void setUp() {
            membershipId = UUID.randomUUID();
            orgId = UUID.randomUUID();

            Organization org = Organization.builder()
                    .name("Test Org")
                    .slug("test-org")
                    .build();
            org.setId(orgId);

            User user = User.builder()
                    .email("test@example.com")
                    .passwordHash("hash")
                    .build();
            user.setId(UUID.randomUUID());

            testMembership = Membership.builder()
                    .organization(org)
                    .user(user)
                    .status(MembershipStatus.ACTIVE)
                    .roles(new HashSet<>())
                    .build();
            testMembership.setId(membershipId);
        }

        @Test
        @DisplayName("should assign role to member")
        void shouldAssignRoleToMember() {
            when(membershipRepository.findById(membershipId)).thenReturn(Optional.of(testMembership));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            rbacService.assignRoleToMember(membershipId, testRoleId, actorId, orgId, ipAddress);

            assertThat(testMembership.getRoles()).contains(testRole);
            verify(membershipRepository).save(testMembership);
            verify(auditService).logRoleAssigned(membershipId, testRoleId, "ADMIN", orgId, actorId, ipAddress);
        }

        @Test
        @DisplayName("should throw conflict when member already has role")
        void shouldThrowConflictWhenMemberAlreadyHasRole() {
            testMembership.getRoles().add(testRole);
            when(membershipRepository.findById(membershipId)).thenReturn(Optional.of(testMembership));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> rbacService.assignRoleToMember(membershipId, testRoleId, actorId, orgId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("already has this role");
                    });
        }

        @Test
        @DisplayName("should remove role from member")
        void shouldRemoveRoleFromMember() {
            Role secondRole = Role.builder().name("USER").build();
            secondRole.setId(UUID.randomUUID());
            testMembership.getRoles().add(testRole);
            testMembership.getRoles().add(secondRole);

            when(membershipRepository.findById(membershipId)).thenReturn(Optional.of(testMembership));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            rbacService.removeRoleFromMember(membershipId, testRoleId, actorId, orgId, ipAddress);

            assertThat(testMembership.getRoles()).doesNotContain(testRole);
            verify(membershipRepository).save(testMembership);
            verify(auditService).logRoleRemoved(membershipId, testRoleId, "ADMIN", orgId, actorId, ipAddress);
        }

        @Test
        @DisplayName("should throw bad request when removing last role")
        void shouldThrowBadRequestWhenRemovingLastRole() {
            testMembership.getRoles().add(testRole);
            when(membershipRepository.findById(membershipId)).thenReturn(Optional.of(testMembership));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> rbacService.removeRoleFromMember(membershipId, testRoleId, actorId, orgId, ipAddress))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("last role");
                    });
        }
    }

    @Nested
    @DisplayName("Mapping Tests")
    class MappingTests {

        @Test
        @DisplayName("should map role to DTO with all permissions")
        void shouldMapRoleToDto() {
            Permission perm2 = Permission.builder()
                    .key("user:write")
                    .build();
            perm2.setId(UUID.randomUUID());
            testRole.getPermissions().add(perm2);

            RoleDto result = rbacService.toRoleDto(testRole);

            assertThat(result.id()).isEqualTo(testRoleId);
            assertThat(result.name()).isEqualTo("ADMIN");
            assertThat(result.description()).isEqualTo("Administrator role");
            assertThat(result.systemRole()).isFalse();
            assertThat(result.permissions()).containsExactlyInAnyOrder("user:read", "user:write");
        }

        @Test
        @DisplayName("should map permission to DTO")
        void shouldMapPermissionToDto() {
            PermissionDto result = rbacService.toPermissionDto(testPermission);

            assertThat(result.id()).isEqualTo(testPermissionId);
            assertThat(result.key()).isEqualTo("user:read");
            assertThat(result.description()).isEqualTo("Read user data");
        }
    }
}
