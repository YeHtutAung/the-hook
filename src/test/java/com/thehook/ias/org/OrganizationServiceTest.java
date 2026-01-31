package com.thehook.ias.org;

import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.org.dto.*;
import com.thehook.ias.rbac.Permission;
import com.thehook.ias.rbac.Role;
import com.thehook.ias.rbac.RoleRepository;
import com.thehook.ias.user.User;
import com.thehook.ias.user.UserRepository;
import com.thehook.ias.user.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationServiceTest {

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private MembershipRepository membershipRepository;

    @Mock
    private InvitationRepository invitationRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditService auditService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private OrganizationService organizationService;

    private User testUser;
    private User platformOwner;
    private Organization testOrg;
    private Role sellerAdminRole;
    private Role endUserRole;
    private Permission invitePermission;
    private Permission readPermission;
    private Membership testMembership;
    private UUID testUserId;
    private UUID platformOwnerId;
    private UUID testOrgId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        platformOwnerId = UUID.randomUUID();
        testOrgId = UUID.randomUUID();

        // Set default values for @Value fields
        ReflectionTestUtils.setField(organizationService, "baseUrl", "http://localhost:9000");
        ReflectionTestUtils.setField(organizationService, "invitationExpiryDays", 7);

        testUser = User.builder()
                .email("test@example.com")
                .displayName("Test User")
                .enabled(true)
                .platformOwner(false)
                .build();
        testUser.setId(testUserId);

        platformOwner = User.builder()
                .email("admin@example.com")
                .displayName("Platform Owner")
                .enabled(true)
                .platformOwner(true)
                .build();
        platformOwner.setId(platformOwnerId);

        testOrg = Organization.builder()
                .name("Test Organization")
                .slug("test-org")
                .enabled(true)
                .createdBy(testUserId)
                .build();
        testOrg.setId(testOrgId);
        testOrg.setCreatedAt(Instant.now());

        invitePermission = Permission.builder()
                .key("member:invite")
                .description("Invite members")
                .build();
        invitePermission.setId(UUID.randomUUID());

        readPermission = Permission.builder()
                .key("member:read")
                .description("Read members")
                .build();
        readPermission.setId(UUID.randomUUID());

        sellerAdminRole = Role.builder()
                .name(Role.SELLER_ADMIN)
                .description("Seller Admin")
                .systemRole(true)
                .permissions(new HashSet<>(Set.of(invitePermission, readPermission)))
                .build();
        sellerAdminRole.setId(UUID.randomUUID());

        endUserRole = Role.builder()
                .name(Role.END_USER)
                .description("End User")
                .systemRole(true)
                .permissions(new HashSet<>(Set.of(readPermission)))
                .build();
        endUserRole.setId(UUID.randomUUID());

        testMembership = Membership.builder()
                .user(testUser)
                .organization(testOrg)
                .status(MembershipStatus.ACTIVE)
                .roles(new HashSet<>(Set.of(sellerAdminRole)))
                .build();
        testMembership.setId(UUID.randomUUID());
        testMembership.setCreatedAt(Instant.now());
    }

    @Nested
    @DisplayName("createOrganization()")
    class CreateOrganizationTests {

        @Test
        @DisplayName("should create organization successfully")
        void shouldCreateOrganization() {
            CreateOrganizationRequest request = new CreateOrganizationRequest("New Org", "new-org");
            String ipAddress = "127.0.0.1";

            when(organizationRepository.existsBySlug("new-org")).thenReturn(false);
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(organizationRepository.save(any(Organization.class))).thenAnswer(invocation -> {
                Organization org = invocation.getArgument(0);
                org.setId(UUID.randomUUID());
                org.setCreatedAt(Instant.now());
                return org;
            });
            when(roleRepository.findByName(Role.SELLER_ADMIN)).thenReturn(Optional.of(sellerAdminRole));
            when(membershipRepository.save(any(Membership.class))).thenAnswer(invocation -> invocation.getArgument(0));

            OrganizationDto result = organizationService.createOrganization(request, testUserId, ipAddress);

            assertThat(result.name()).isEqualTo("New Org");
            assertThat(result.slug()).isEqualTo("new-org");
            assertThat(result.enabled()).isTrue();

            verify(organizationRepository).save(any(Organization.class));
            verify(membershipRepository).save(any(Membership.class));
            verify(auditService).logOrganizationCreated(any(UUID.class), eq(testUserId), eq(ipAddress));
        }

        @Test
        @DisplayName("should normalize slug to lowercase")
        void shouldNormalizeSlug() {
            CreateOrganizationRequest request = new CreateOrganizationRequest("New Org", "NEW-ORG");

            when(organizationRepository.existsBySlug("new-org")).thenReturn(false);
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(organizationRepository.save(any(Organization.class))).thenAnswer(invocation -> {
                Organization org = invocation.getArgument(0);
                org.setId(UUID.randomUUID());
                org.setCreatedAt(Instant.now());
                return org;
            });
            when(roleRepository.findByName(Role.SELLER_ADMIN)).thenReturn(Optional.of(sellerAdminRole));
            when(membershipRepository.save(any(Membership.class))).thenAnswer(invocation -> invocation.getArgument(0));

            OrganizationDto result = organizationService.createOrganization(request, testUserId, "127.0.0.1");

            assertThat(result.slug()).isEqualTo("new-org");
            verify(organizationRepository).existsBySlug("new-org");
        }

        @Test
        @DisplayName("should throw conflict when slug already exists")
        void shouldThrowConflictWhenSlugExists() {
            CreateOrganizationRequest request = new CreateOrganizationRequest("Duplicate Org", "existing-slug");

            when(organizationRepository.existsBySlug("existing-slug")).thenReturn(true);

            assertThatThrownBy(() -> organizationService.createOrganization(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("slug already exists");
                    });

            verify(organizationRepository, never()).save(any());
        }

        @Test
        @DisplayName("should add creator as SELLER_ADMIN")
        void shouldAddCreatorAsSellerAdmin() {
            CreateOrganizationRequest request = new CreateOrganizationRequest("New Org", "new-org");

            when(organizationRepository.existsBySlug("new-org")).thenReturn(false);
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(organizationRepository.save(any(Organization.class))).thenAnswer(invocation -> {
                Organization org = invocation.getArgument(0);
                org.setId(UUID.randomUUID());
                org.setCreatedAt(Instant.now());
                return org;
            });
            when(roleRepository.findByName(Role.SELLER_ADMIN)).thenReturn(Optional.of(sellerAdminRole));
            when(membershipRepository.save(any(Membership.class))).thenAnswer(invocation -> invocation.getArgument(0));

            organizationService.createOrganization(request, testUserId, "127.0.0.1");

            ArgumentCaptor<Membership> membershipCaptor = ArgumentCaptor.forClass(Membership.class);
            verify(membershipRepository).save(membershipCaptor.capture());

            Membership savedMembership = membershipCaptor.getValue();
            assertThat(savedMembership.getUser()).isEqualTo(testUser);
            assertThat(savedMembership.getStatus()).isEqualTo(MembershipStatus.ACTIVE);
            assertThat(savedMembership.getRoles()).contains(sellerAdminRole);
        }
    }

    @Nested
    @DisplayName("verifyMembership()")
    class VerifyMembershipTests {

        @Test
        @DisplayName("should allow platform owner without membership")
        void shouldAllowPlatformOwner() {
            when(userRepository.findById(platformOwnerId)).thenReturn(Optional.of(platformOwner));

            // Should not throw
            organizationService.verifyMembership(platformOwnerId, testOrgId, "any:permission");

            // Should not check membership for platform owner
            verify(membershipRepository, never()).findActiveByUserIdAndOrgId(any(), any());
        }

        @Test
        @DisplayName("should verify membership without permission check")
        void shouldVerifyMembershipWithoutPermission() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            organizationService.verifyMembership(testUserId, testOrgId, null);

            verify(membershipRepository).findActiveByUserIdAndOrgId(testUserId, testOrgId);
        }

        @Test
        @DisplayName("should verify membership with permission check")
        void shouldVerifyMembershipWithPermission() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            organizationService.verifyMembership(testUserId, testOrgId, "member:invite");

            verify(membershipRepository).findActiveByUserIdAndOrgId(testUserId, testOrgId);
        }

        @Test
        @DisplayName("should throw forbidden when not a member")
        void shouldThrowForbiddenWhenNotMember() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> organizationService.verifyMembership(testUserId, testOrgId, null))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                        assertThat(iasEx.getMessage()).contains("Not a member");
                    });
        }

        @Test
        @DisplayName("should throw forbidden when membership is not active")
        void shouldThrowForbiddenWhenNotActive() {
            testMembership.setStatus(MembershipStatus.SUSPENDED);
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            assertThatThrownBy(() -> organizationService.verifyMembership(testUserId, testOrgId, null))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                        assertThat(iasEx.getMessage()).contains("not active");
                    });
        }

        @Test
        @DisplayName("should throw forbidden when missing permission")
        void shouldThrowForbiddenWhenMissingPermission() {
            // Use end user role which doesn't have invite permission
            testMembership.setRoles(new HashSet<>(Set.of(endUserRole)));
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            assertThatThrownBy(() -> organizationService.verifyMembership(testUserId, testOrgId, "member:invite"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                        assertThat(iasEx.getMessage()).contains("Missing required permission");
                    });
        }
    }

    @Nested
    @DisplayName("inviteMember()")
    class InviteMemberTests {

        private InviteMemberRequest inviteRequest;

        @BeforeEach
        void setUp() {
            inviteRequest = new InviteMemberRequest("invitee@example.com", endUserRole.getId());
        }

        @Test
        @DisplayName("should create invitation successfully")
        void shouldCreateInvitation() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));
            when(organizationRepository.findById(testOrgId)).thenReturn(Optional.of(testOrg));
            when(roleRepository.findById(endUserRole.getId())).thenReturn(Optional.of(endUserRole));
            when(invitationRepository.existsByOrganizationIdAndEmailAndStatus(
                    testOrgId, "invitee@example.com", InvitationStatus.PENDING)).thenReturn(false);
            when(userRepository.findByEmail("invitee@example.com")).thenReturn(Optional.empty());
            when(invitationRepository.save(any(Invitation.class))).thenAnswer(invocation -> {
                Invitation inv = invocation.getArgument(0);
                inv.setId(UUID.randomUUID());
                inv.setCreatedAt(Instant.now());
                return inv;
            });

            InvitationDto result = organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1");

            assertThat(result.email()).isEqualTo("invitee@example.com");
            assertThat(result.status()).isEqualTo(InvitationStatus.PENDING);
            assertThat(result.roleName()).isEqualTo(Role.END_USER);
            assertThat(result.token()).isNotBlank();

            verify(invitationRepository).save(any(Invitation.class));
            verify(emailService).sendInvitationEmail(eq("invitee@example.com"), eq("Test Organization"), eq("Test User"), anyString());
        }

        @Test
        @DisplayName("should normalize email to lowercase")
        void shouldNormalizeEmail() {
            inviteRequest = new InviteMemberRequest("INVITEE@EXAMPLE.COM", endUserRole.getId());

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));
            when(organizationRepository.findById(testOrgId)).thenReturn(Optional.of(testOrg));
            when(roleRepository.findById(endUserRole.getId())).thenReturn(Optional.of(endUserRole));
            when(invitationRepository.existsByOrganizationIdAndEmailAndStatus(
                    testOrgId, "invitee@example.com", InvitationStatus.PENDING)).thenReturn(false);
            when(userRepository.findByEmail("invitee@example.com")).thenReturn(Optional.empty());
            when(invitationRepository.save(any(Invitation.class))).thenAnswer(invocation -> {
                Invitation inv = invocation.getArgument(0);
                inv.setId(UUID.randomUUID());
                inv.setCreatedAt(Instant.now());
                return inv;
            });

            InvitationDto result = organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1");

            assertThat(result.email()).isEqualTo("invitee@example.com");
        }

        @Test
        @DisplayName("should throw forbidden without invite permission")
        void shouldThrowForbiddenWithoutPermission() {
            testMembership.setRoles(new HashSet<>(Set.of(endUserRole))); // No invite permission

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            assertThatThrownBy(() -> organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    });
        }

        @Test
        @DisplayName("should throw conflict when pending invitation exists")
        void shouldThrowConflictWhenPendingInvitationExists() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));
            when(organizationRepository.findById(testOrgId)).thenReturn(Optional.of(testOrg));
            when(roleRepository.findById(endUserRole.getId())).thenReturn(Optional.of(endUserRole));
            when(invitationRepository.existsByOrganizationIdAndEmailAndStatus(
                    testOrgId, "invitee@example.com", InvitationStatus.PENDING)).thenReturn(true);

            assertThatThrownBy(() -> organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("Pending invitation already exists");
                    });
        }

        @Test
        @DisplayName("should throw conflict when user is already a member")
        void shouldThrowConflictWhenAlreadyMember() {
            User existingUser = User.builder()
                    .email("invitee@example.com")
                    .build();
            existingUser.setId(UUID.randomUUID());

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));
            when(organizationRepository.findById(testOrgId)).thenReturn(Optional.of(testOrg));
            when(roleRepository.findById(endUserRole.getId())).thenReturn(Optional.of(endUserRole));
            when(invitationRepository.existsByOrganizationIdAndEmailAndStatus(
                    testOrgId, "invitee@example.com", InvitationStatus.PENDING)).thenReturn(false);
            when(userRepository.findByEmail("invitee@example.com")).thenReturn(Optional.of(existingUser));
            when(membershipRepository.existsByUserIdAndOrganizationId(existingUser.getId(), testOrgId)).thenReturn(true);

            assertThatThrownBy(() -> organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("already a member");
                    });
        }

        @Test
        @DisplayName("should throw bad request when organization is disabled")
        void shouldThrowBadRequestWhenOrgDisabled() {
            testOrg.setEnabled(false);

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));
            when(organizationRepository.findById(testOrgId)).thenReturn(Optional.of(testOrg));

            assertThatThrownBy(() -> organizationService.inviteMember(testOrgId, inviteRequest, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("disabled");
                    });
        }
    }

    @Nested
    @DisplayName("acceptInvitation()")
    class AcceptInvitationTests {

        private Invitation testInvitation;

        @BeforeEach
        void setUp() {
            testInvitation = Invitation.builder()
                    .organization(testOrg)
                    .email("test@example.com")
                    .token("valid-token")
                    .role(endUserRole)
                    .status(InvitationStatus.PENDING)
                    .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                    .createdBy(UUID.randomUUID())
                    .build();
            testInvitation.setId(UUID.randomUUID());
        }

        @Test
        @DisplayName("should accept invitation successfully")
        void shouldAcceptInvitation() {
            AcceptInvitationRequest request = new AcceptInvitationRequest("valid-token");

            when(invitationRepository.findByToken("valid-token")).thenReturn(Optional.of(testInvitation));
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.existsByUserIdAndOrganizationId(testUserId, testOrgId)).thenReturn(false);
            when(membershipRepository.save(any(Membership.class))).thenAnswer(invocation -> {
                Membership m = invocation.getArgument(0);
                m.setId(UUID.randomUUID());
                m.setCreatedAt(Instant.now());
                return m;
            });
            when(invitationRepository.save(any(Invitation.class))).thenAnswer(invocation -> invocation.getArgument(0));

            MembershipDto result = organizationService.acceptInvitation(request, testUserId, "127.0.0.1");

            assertThat(result.organizationId()).isEqualTo(testOrgId);
            assertThat(result.status()).isEqualTo(MembershipStatus.ACTIVE);
            assertThat(result.roles()).contains(Role.END_USER);

            assertThat(testInvitation.getStatus()).isEqualTo(InvitationStatus.ACCEPTED);
            assertThat(testInvitation.getAcceptedAt()).isNotNull();
            assertThat(testInvitation.getAcceptedBy()).isEqualTo(testUserId);

            verify(membershipRepository).save(any(Membership.class));
            verify(invitationRepository).save(testInvitation);
            verify(auditService).logInvitationAccepted(any(UUID.class), eq(testUserId), eq(testOrgId), eq("127.0.0.1"));
        }

        @Test
        @DisplayName("should throw bad request for invalid token")
        void shouldThrowBadRequestForInvalidToken() {
            AcceptInvitationRequest request = new AcceptInvitationRequest("invalid-token");

            when(invitationRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> organizationService.acceptInvitation(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("Invalid invitation token");
                    });
        }

        @Test
        @DisplayName("should throw bad request when invitation is not pending")
        void shouldThrowBadRequestWhenNotPending() {
            testInvitation.setStatus(InvitationStatus.ACCEPTED);
            AcceptInvitationRequest request = new AcceptInvitationRequest("valid-token");

            when(invitationRepository.findByToken("valid-token")).thenReturn(Optional.of(testInvitation));

            assertThatThrownBy(() -> organizationService.acceptInvitation(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("no longer pending");
                    });
        }

        @Test
        @DisplayName("should throw bad request and mark expired when invitation has expired")
        void shouldThrowBadRequestWhenExpired() {
            testInvitation.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
            AcceptInvitationRequest request = new AcceptInvitationRequest("valid-token");

            when(invitationRepository.findByToken("valid-token")).thenReturn(Optional.of(testInvitation));
            when(invitationRepository.save(any(Invitation.class))).thenAnswer(invocation -> invocation.getArgument(0));

            assertThatThrownBy(() -> organizationService.acceptInvitation(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("expired");
                    });

            assertThat(testInvitation.getStatus()).isEqualTo(InvitationStatus.EXPIRED);
        }

        @Test
        @DisplayName("should throw forbidden when email does not match")
        void shouldThrowForbiddenWhenEmailMismatch() {
            testInvitation.setEmail("other@example.com");
            AcceptInvitationRequest request = new AcceptInvitationRequest("valid-token");

            when(invitationRepository.findByToken("valid-token")).thenReturn(Optional.of(testInvitation));
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> organizationService.acceptInvitation(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                        assertThat(iasEx.getMessage()).contains("does not match");
                    });
        }

        @Test
        @DisplayName("should throw conflict when already a member")
        void shouldThrowConflictWhenAlreadyMember() {
            AcceptInvitationRequest request = new AcceptInvitationRequest("valid-token");

            when(invitationRepository.findByToken("valid-token")).thenReturn(Optional.of(testInvitation));
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.existsByUserIdAndOrganizationId(testUserId, testOrgId)).thenReturn(true);

            assertThatThrownBy(() -> organizationService.acceptInvitation(request, testUserId, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("Already a member");
                    });
        }
    }

    @Nested
    @DisplayName("getUserMemberships()")
    class GetUserMembershipsTests {

        @Test
        @DisplayName("should return user memberships")
        void shouldReturnMemberships() {
            when(membershipRepository.findActiveByUserId(testUserId)).thenReturn(List.of(testMembership));

            List<MembershipDto> result = organizationService.getUserMemberships(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).organizationId()).isEqualTo(testOrgId);
            assertThat(result.get(0).organizationName()).isEqualTo("Test Organization");
            assertThat(result.get(0).status()).isEqualTo(MembershipStatus.ACTIVE);
        }

        @Test
        @DisplayName("should return empty list when user has no memberships")
        void shouldReturnEmptyListWhenNoMemberships() {
            when(membershipRepository.findActiveByUserId(testUserId)).thenReturn(List.of());

            List<MembershipDto> result = organizationService.getUserMemberships(testUserId);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("hasPermission()")
    class HasPermissionTests {

        @Test
        @DisplayName("should return true for platform owner")
        void shouldReturnTrueForPlatformOwner() {
            when(userRepository.findById(platformOwnerId)).thenReturn(Optional.of(platformOwner));

            boolean result = organizationService.hasPermission(platformOwnerId, testOrgId, "any:permission");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return true when user has permission")
        void shouldReturnTrueWhenHasPermission() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            boolean result = organizationService.hasPermission(testUserId, testOrgId, "member:invite");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false when user lacks permission")
        void shouldReturnFalseWhenLacksPermission() {
            testMembership.setRoles(new HashSet<>(Set.of(endUserRole)));
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.of(testMembership));

            boolean result = organizationService.hasPermission(testUserId, testOrgId, "member:invite");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false when user is not a member")
        void shouldReturnFalseWhenNotMember() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(membershipRepository.findActiveByUserIdAndOrgId(testUserId, testOrgId))
                    .thenReturn(Optional.empty());

            boolean result = organizationService.hasPermission(testUserId, testOrgId, "member:invite");

            assertThat(result).isFalse();
        }
    }
}
