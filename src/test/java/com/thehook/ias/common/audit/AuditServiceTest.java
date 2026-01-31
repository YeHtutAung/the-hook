package com.thehook.ias.common.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditService auditService;

    private UUID testUserId;
    private UUID testOrgId;
    private String testIpAddress;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        testOrgId = UUID.randomUUID();
        testIpAddress = "127.0.0.1";
    }

    @Nested
    @DisplayName("log()")
    class LogTests {

        @Test
        @DisplayName("should create audit log with all fields")
        void shouldCreateAuditLogWithAllFields() {
            UUID entityId = UUID.randomUUID();
            Map<String, Object> details = Map.of("key", "value");

            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.log("TEST_ACTION", "TestEntity", entityId, testUserId, testOrgId, details, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getAction()).isEqualTo("TEST_ACTION");
            assertThat(savedLog.getEntityType()).isEqualTo("TestEntity");
            assertThat(savedLog.getEntityId()).isEqualTo(entityId);
            assertThat(savedLog.getActorId()).isEqualTo(testUserId);
            assertThat(savedLog.getOrganizationId()).isEqualTo(testOrgId);
            assertThat(savedLog.getDetails()).isEqualTo(details);
            assertThat(savedLog.getIpAddress()).isEqualTo(testIpAddress);
        }

        @Test
        @DisplayName("should handle null details")
        void shouldHandleNullDetails() {
            UUID entityId = UUID.randomUUID();

            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.log("TEST_ACTION", "TestEntity", entityId, testUserId, testOrgId, null, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getDetails()).isNull();
        }

        @Test
        @DisplayName("should handle null organization id")
        void shouldHandleNullOrgId() {
            UUID entityId = UUID.randomUUID();

            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.log("TEST_ACTION", "TestEntity", entityId, testUserId, null, null, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getOrganizationId()).isNull();
        }

        @Test
        @DisplayName("should not throw exception on repository error")
        void shouldNotThrowOnRepositoryError() {
            UUID entityId = UUID.randomUUID();

            when(auditLogRepository.save(any(AuditLog.class))).thenThrow(new RuntimeException("DB error"));

            // Should not throw
            auditService.log("TEST_ACTION", "TestEntity", entityId, testUserId, testOrgId, null, testIpAddress);

            verify(auditLogRepository).save(any(AuditLog.class));
        }
    }

    @Nested
    @DisplayName("logRoleAssignment()")
    class LogRoleAssignmentTests {

        @Test
        @DisplayName("should log role assignment with correct parameters")
        void shouldLogRoleAssignment() {
            UUID membershipId = UUID.randomUUID();
            UUID roleId = UUID.randomUUID();

            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.logRoleAssignment(membershipId, roleId, testUserId, testOrgId, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getAction()).isEqualTo("ROLE_ASSIGNED");
            assertThat(savedLog.getEntityType()).isEqualTo("Membership");
            assertThat(savedLog.getEntityId()).isEqualTo(membershipId);
            assertThat(savedLog.getActorId()).isEqualTo(testUserId);
            assertThat(savedLog.getOrganizationId()).isEqualTo(testOrgId);
            assertThat(savedLog.getDetails()).containsEntry("roleId", roleId.toString());
            assertThat(savedLog.getIpAddress()).isEqualTo(testIpAddress);
        }
    }

    @Nested
    @DisplayName("logInvitationAccepted()")
    class LogInvitationAcceptedTests {

        @Test
        @DisplayName("should log invitation accepted with correct parameters")
        void shouldLogInvitationAccepted() {
            UUID invitationId = UUID.randomUUID();

            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.logInvitationAccepted(invitationId, testUserId, testOrgId, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getAction()).isEqualTo("INVITATION_ACCEPTED");
            assertThat(savedLog.getEntityType()).isEqualTo("Invitation");
            assertThat(savedLog.getEntityId()).isEqualTo(invitationId);
            assertThat(savedLog.getActorId()).isEqualTo(testUserId);
            assertThat(savedLog.getOrganizationId()).isEqualTo(testOrgId);
            assertThat(savedLog.getDetails()).isNull();
            assertThat(savedLog.getIpAddress()).isEqualTo(testIpAddress);
        }
    }

    @Nested
    @DisplayName("logUserRegistered()")
    class LogUserRegisteredTests {

        @Test
        @DisplayName("should log user registered with correct parameters")
        void shouldLogUserRegistered() {
            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.logUserRegistered(testUserId, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getAction()).isEqualTo("USER_REGISTERED");
            assertThat(savedLog.getEntityType()).isEqualTo("User");
            assertThat(savedLog.getEntityId()).isEqualTo(testUserId);
            assertThat(savedLog.getActorId()).isEqualTo(testUserId);
            assertThat(savedLog.getOrganizationId()).isNull();
            assertThat(savedLog.getDetails()).isNull();
            assertThat(savedLog.getIpAddress()).isEqualTo(testIpAddress);
        }
    }

    @Nested
    @DisplayName("logOrganizationCreated()")
    class LogOrganizationCreatedTests {

        @Test
        @DisplayName("should log organization created with correct parameters")
        void shouldLogOrganizationCreated() {
            when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

            auditService.logOrganizationCreated(testOrgId, testUserId, testIpAddress);

            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog savedLog = captor.getValue();
            assertThat(savedLog.getAction()).isEqualTo("ORG_CREATED");
            assertThat(savedLog.getEntityType()).isEqualTo("Organization");
            assertThat(savedLog.getEntityId()).isEqualTo(testOrgId);
            assertThat(savedLog.getActorId()).isEqualTo(testUserId);
            assertThat(savedLog.getOrganizationId()).isEqualTo(testOrgId);
            assertThat(savedLog.getDetails()).isNull();
            assertThat(savedLog.getIpAddress()).isEqualTo(testIpAddress);
        }
    }
}
