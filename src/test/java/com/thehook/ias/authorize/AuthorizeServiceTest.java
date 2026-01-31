package com.thehook.ias.authorize;

import com.thehook.ias.authorize.dto.AuthorizeRequest;
import com.thehook.ias.authorize.dto.AuthorizeResponse;
import com.thehook.ias.org.Membership;
import com.thehook.ias.org.MembershipRepository;
import com.thehook.ias.org.MembershipStatus;
import com.thehook.ias.org.Organization;
import com.thehook.ias.rbac.Permission;
import com.thehook.ias.rbac.Role;
import com.thehook.ias.user.User;
import com.thehook.ias.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizeServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private MembershipRepository membershipRepository;

    @InjectMocks
    private AuthorizeService authorizeService;

    private User testUser;
    private Organization testOrg;
    private Role testRole;
    private Permission testPermission;
    private Membership testMembership;
    private UUID testUserId;
    private UUID testOrgId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        testOrgId = UUID.randomUUID();

        testUser = User.builder()
                .email("test@example.com")
                .displayName("Test User")
                .enabled(true)
                .platformOwner(false)
                .build();
        testUser.setId(testUserId);

        testOrg = Organization.builder()
                .name("Test Org")
                .slug("test-org")
                .enabled(true)
                .build();
        testOrg.setId(testOrgId);

        testPermission = Permission.builder()
                .key("resource:read")
                .description("Read resource")
                .build();
        testPermission.setId(UUID.randomUUID());

        testRole = Role.builder()
                .name("MEMBER")
                .permissions(new HashSet<>(Set.of(testPermission)))
                .build();
        testRole.setId(UUID.randomUUID());

        testMembership = Membership.builder()
                .user(testUser)
                .organization(testOrg)
                .status(MembershipStatus.ACTIVE)
                .roles(new HashSet<>(Set.of(testRole)))
                .build();
        testMembership.setId(UUID.randomUUID());
    }

    @Nested
    @DisplayName("User Not Found")
    class UserNotFoundTests {

        @Test
        @DisplayName("should deny when user not found")
        void shouldDenyWhenUserNotFound() {
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.empty());

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).isEqualTo("User not found");
        }
    }

    @Nested
    @DisplayName("User Disabled")
    class UserDisabledTests {

        @Test
        @DisplayName("should deny when user is disabled")
        void shouldDenyWhenUserDisabled() {
            testUser.setEnabled(false);
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).isEqualTo("User is disabled");
        }
    }

    @Nested
    @DisplayName("Platform Owner")
    class PlatformOwnerTests {

        @Test
        @DisplayName("should allow platform owner for any permission")
        void shouldAllowPlatformOwner() {
            testUser.setPlatformOwner(true);
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "any:permission");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isTrue();
            assertThat(response.reason()).isNull();
        }
    }

    @Nested
    @DisplayName("Membership Checks")
    class MembershipChecksTests {

        @Test
        @DisplayName("should deny when not a member of organization")
        void shouldDenyWhenNotMember() {
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.empty());

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).isEqualTo("Not a member of this organization");
        }

        @Test
        @DisplayName("should deny when membership is not active")
        void shouldDenyWhenMembershipNotActive() {
            testMembership.setStatus(MembershipStatus.SUSPENDED);
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).isEqualTo("Membership is not active");
        }
    }

    @Nested
    @DisplayName("Permission Checks")
    class PermissionChecksTests {

        @Test
        @DisplayName("should allow when user has required permission")
        void shouldAllowWhenHasPermission() {
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isTrue();
            assertThat(response.reason()).isNull();
        }

        @Test
        @DisplayName("should deny when missing required permission")
        void shouldDenyWhenMissingPermission() {
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:write");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).contains("Missing required permission");
            assertThat(response.reason()).contains("resource:write");
        }

        @Test
        @DisplayName("should allow when permission exists in any role")
        void shouldAllowWhenPermissionInAnyRole() {
            Permission writePermission = Permission.builder()
                    .key("resource:write")
                    .build();
            writePermission.setId(UUID.randomUUID());

            Role adminRole = Role.builder()
                    .name("ADMIN")
                    .permissions(new HashSet<>(Set.of(writePermission)))
                    .build();
            adminRole.setId(UUID.randomUUID());

            testMembership.getRoles().add(adminRole);

            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:write");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isTrue();
        }

        @Test
        @DisplayName("should check permission across multiple roles")
        void shouldCheckPermissionAcrossMultipleRoles() {
            Role emptyRole = Role.builder()
                    .name("EMPTY_ROLE")
                    .permissions(new HashSet<>())
                    .build();
            emptyRole.setId(UUID.randomUUID());

            testMembership.getRoles().add(emptyRole);

            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("should handle user with no roles")
        void shouldHandleUserWithNoRoles() {
            testMembership.setRoles(new HashSet<>());

            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).contains("Missing required permission");
        }

        @Test
        @DisplayName("should handle role with no permissions")
        void shouldHandleRoleWithNoPermissions() {
            testRole.setPermissions(new HashSet<>());

            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
            assertThat(response.reason()).contains("Missing required permission");
        }

        @Test
        @DisplayName("should match permission key exactly")
        void shouldMatchPermissionKeyExactly() {
            AuthorizeRequest request = new AuthorizeRequest(testUserId, testOrgId, "resource:read:all");
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            AuthorizeResponse response = authorizeService.authorize(request);

            assertThat(response.allowed()).isFalse();
        }
    }
}
