package com.thehook.ias.user;

import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.user.dto.RegisterRequest;
import com.thehook.ias.user.dto.RegisterResponse;
import com.thehook.ias.user.dto.UserDto;
import com.thehook.ias.user.dto.VerifyEmailResponse;
import com.thehook.ias.user.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailVerificationRepository emailVerificationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private UserService userService;

    private User testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        testUser = User.builder()
                .email("test@example.com")
                .passwordHash("encodedPassword")
                .displayName("Test User")
                .emailVerified(false)
                .enabled(true)
                .platformOwner(false)
                .build();
        testUser.setId(testUserId);
        testUser.setCreatedAt(Instant.now());

        // Set default values for @Value fields
        ReflectionTestUtils.setField(userService, "baseUrl", "http://localhost:9000");
        ReflectionTestUtils.setField(userService, "verificationExpiryHours", 24);
    }

    @Nested
    @DisplayName("registerUser()")
    class RegisterUserTests {

        @Test
        @DisplayName("should register new user successfully")
        void shouldRegisterNewUser() {
            RegisterRequest request = new RegisterRequest("NEW@example.com", "Password123", "New User");
            String ipAddress = "127.0.0.1";

            when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123")).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(any())).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
                EmailVerification v = invocation.getArgument(0);
                v.setId(UUID.randomUUID());
                return v;
            });

            RegisterResponse result = userService.registerUser(request, ipAddress);

            assertThat(result.email()).isEqualTo("new@example.com");
            assertThat(result.displayName()).isEqualTo("New User");
            assertThat(result.emailVerified()).isFalse();
            assertThat(result.verificationToken()).isNotBlank();
            assertThat(result.message()).contains("verify");

            verify(userRepository).existsByEmail("new@example.com");
            verify(passwordEncoder).encode("Password123");
            verify(userRepository).save(any(User.class));
            verify(emailVerificationRepository).save(any(EmailVerification.class));
            verify(emailService).sendVerificationEmail(eq("new@example.com"), eq("New User"), anyString());
            verify(auditService).logUserRegistered(any(UUID.class), eq(ipAddress));
        }

        @Test
        @DisplayName("should normalize email to lowercase")
        void shouldNormalizeEmailToLowercase() {
            RegisterRequest request = new RegisterRequest("TEST@EXAMPLE.COM", "Password123", "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(any())).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> invocation.getArgument(0));

            RegisterResponse result = userService.registerUser(request, "127.0.0.1");

            assertThat(result.email()).isEqualTo("test@example.com");
            verify(userRepository).existsByEmail("test@example.com");
        }

        @Test
        @DisplayName("should trim display name")
        void shouldTrimDisplayName() {
            RegisterRequest request = new RegisterRequest("test@example.com", "Password123", "  Test User  ");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(any())).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> invocation.getArgument(0));

            RegisterResponse result = userService.registerUser(request, "127.0.0.1");

            assertThat(result.displayName()).isEqualTo("Test User");
        }

        @Test
        @DisplayName("should throw conflict when email already exists")
        void shouldThrowConflictWhenEmailExists() {
            RegisterRequest request = new RegisterRequest("existing@example.com", "Password123", "Test User");

            when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

            assertThatThrownBy(() -> userService.registerUser(request, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(iasEx.getMessage()).contains("already registered");
                    });

            verify(userRepository, never()).save(any());
            verify(auditService, never()).logUserRegistered(any(), anyString());
        }

        @ParameterizedTest
        @ValueSource(strings = {"short", "1234567", "abc"})
        @DisplayName("should reject password shorter than 8 characters")
        void shouldRejectShortPassword(String shortPassword) {
            RegisterRequest request = new RegisterRequest("test@example.com", shortPassword, "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            assertThatThrownBy(() -> userService.registerUser(request, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("8 characters");
                    });
        }

        @Test
        @DisplayName("should reject password without letters")
        void shouldRejectPasswordWithoutLetters() {
            RegisterRequest request = new RegisterRequest("test@example.com", "12345678", "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            assertThatThrownBy(() -> userService.registerUser(request, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("letter").contains("digit");
                    });
        }

        @Test
        @DisplayName("should reject password without digits")
        void shouldRejectPasswordWithoutDigits() {
            RegisterRequest request = new RegisterRequest("test@example.com", "abcdefgh", "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            assertThatThrownBy(() -> userService.registerUser(request, "127.0.0.1"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("letter").contains("digit");
                    });
        }

        @Test
        @DisplayName("should hash password before storing")
        void shouldHashPassword() {
            RegisterRequest request = new RegisterRequest("test@example.com", "Password123", "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123")).thenReturn("$2a$10$hashedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(any())).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> invocation.getArgument(0));

            userService.registerUser(request, "127.0.0.1");

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());

            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getPasswordHash()).isEqualTo("$2a$10$hashedPassword");
            assertThat(savedUser.getPasswordHash()).isNotEqualTo("Password123");
        }

        @Test
        @DisplayName("should set emailVerified to false on registration")
        void shouldSetEmailVerifiedToFalse() {
            RegisterRequest request = new RegisterRequest("test@example.com", "Password123", "Test User");

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encoded");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(any())).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> invocation.getArgument(0));

            RegisterResponse result = userService.registerUser(request, "127.0.0.1");

            assertThat(result.emailVerified()).isFalse();

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().isEmailVerified()).isFalse();
        }
    }

    @Nested
    @DisplayName("createEmailVerification()")
    class CreateEmailVerificationTests {

        @Test
        @DisplayName("should create verification token with 24-hour expiry")
        void shouldCreateVerificationToken() {
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(testUserId)).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
                EmailVerification v = invocation.getArgument(0);
                v.setId(UUID.randomUUID());
                return v;
            });

            Instant beforeCreate = Instant.now();
            EmailVerification result = userService.createEmailVerification(testUser);
            Instant afterCreate = Instant.now();

            assertThat(result.getUser()).isEqualTo(testUser);
            assertThat(result.getToken()).isNotBlank();
            assertThat(result.getToken()).hasSize(36); // UUID format
            assertThat(result.getExpiresAt()).isAfter(beforeCreate.plus(23, ChronoUnit.HOURS));
            assertThat(result.getExpiresAt()).isBefore(afterCreate.plus(25, ChronoUnit.HOURS));
        }

        @Test
        @DisplayName("should invalidate existing unverified tokens")
        void shouldInvalidateExistingTokens() {
            EmailVerification existingToken = EmailVerification.builder()
                    .user(testUser)
                    .token("old-token")
                    .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    .build();
            existingToken.setId(UUID.randomUUID());

            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(testUserId))
                    .thenReturn(Optional.of(existingToken));
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
                EmailVerification v = invocation.getArgument(0);
                if (v.getId() == null) {
                    v.setId(UUID.randomUUID());
                }
                return v;
            });

            userService.createEmailVerification(testUser);

            // Verify existing token was marked as used
            assertThat(existingToken.getVerifiedAt()).isNotNull();
            verify(emailVerificationRepository, times(2)).save(any(EmailVerification.class));
        }
    }

    @Nested
    @DisplayName("verifyEmailWithResponse()")
    class VerifyEmailTests {

        @Test
        @DisplayName("should verify email successfully")
        void shouldVerifyEmailSuccessfully() {
            String token = "valid-token";
            EmailVerification verification = EmailVerification.builder()
                    .user(testUser)
                    .token(token)
                    .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    .verifiedAt(null)
                    .build();
            verification.setId(UUID.randomUUID());

            when(emailVerificationRepository.findByToken(token)).thenReturn(Optional.of(verification));
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> invocation.getArgument(0));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            VerifyEmailResponse result = userService.verifyEmailWithResponse(token);

            assertThat(result.emailVerified()).isTrue();
            assertThat(result.userId()).isEqualTo(testUserId);
            assertThat(result.email()).isEqualTo("test@example.com");
            assertThat(result.message()).contains("successfully");

            assertThat(verification.getVerifiedAt()).isNotNull();
            assertThat(testUser.isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("should throw exception for invalid token")
        void shouldThrowExceptionForInvalidToken() {
            when(emailVerificationRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.verifyEmailWithResponse("invalid-token"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("Invalid");
                    });
        }

        @Test
        @DisplayName("should throw exception for expired token")
        void shouldThrowExceptionForExpiredToken() {
            String token = "expired-token";
            EmailVerification verification = EmailVerification.builder()
                    .user(testUser)
                    .token(token)
                    .expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
                    .verifiedAt(null)
                    .build();
            verification.setId(UUID.randomUUID());

            when(emailVerificationRepository.findByToken(token)).thenReturn(Optional.of(verification));

            assertThatThrownBy(() -> userService.verifyEmailWithResponse(token))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("expired");
                    });
        }

        @Test
        @DisplayName("should throw exception for already verified token")
        void shouldThrowExceptionForAlreadyVerified() {
            String token = "used-token";
            EmailVerification verification = EmailVerification.builder()
                    .user(testUser)
                    .token(token)
                    .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    .verifiedAt(Instant.now().minus(1, ChronoUnit.HOURS))
                    .build();
            verification.setId(UUID.randomUUID());

            when(emailVerificationRepository.findByToken(token)).thenReturn(Optional.of(verification));

            assertThatThrownBy(() -> userService.verifyEmailWithResponse(token))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("already been verified");
                    });
        }
    }

    @Nested
    @DisplayName("resendVerificationEmail()")
    class ResendVerificationTests {

        @Test
        @DisplayName("should resend verification email")
        void shouldResendVerification() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(testUserId)).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
                EmailVerification v = invocation.getArgument(0);
                v.setId(UUID.randomUUID());
                return v;
            });

            String token = userService.resendVerificationEmail("test@example.com");

            assertThat(token).isNotBlank();
            verify(emailService).sendVerificationEmail(eq("test@example.com"), eq("Test User"), anyString());
        }

        @Test
        @DisplayName("should normalize email when resending")
        void shouldNormalizeEmailWhenResending() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(testUserId)).thenReturn(Optional.empty());
            when(emailVerificationRepository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
                EmailVerification v = invocation.getArgument(0);
                v.setId(UUID.randomUUID());
                return v;
            });

            userService.resendVerificationEmail("TEST@EXAMPLE.COM");

            verify(userRepository).findByEmail("test@example.com");
        }

        @Test
        @DisplayName("should throw exception if user not found")
        void shouldThrowExceptionIfUserNotFound() {
            when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.resendVerificationEmail("unknown@example.com"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }

        @Test
        @DisplayName("should throw exception if email already verified")
        void shouldThrowExceptionIfAlreadyVerified() {
            testUser.setEmailVerified(true);
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> userService.resendVerificationEmail("test@example.com"))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(iasEx.getMessage()).contains("already verified");
                    });
        }
    }

    @Nested
    @DisplayName("findById()")
    class FindByIdTests {

        @Test
        @DisplayName("should find user by id")
        void shouldFindUserById() {
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            User result = userService.findById(testUserId);

            assertThat(result).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should throw not found when user does not exist")
        void shouldThrowNotFoundWhenUserDoesNotExist() {
            UUID unknownId = UUID.randomUUID();
            when(userRepository.findById(unknownId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.findById(unknownId))
                    .isInstanceOf(IasException.class)
                    .satisfies(ex -> {
                        IasException iasEx = (IasException) ex;
                        assertThat(iasEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    });
        }
    }

    @Nested
    @DisplayName("findByEmail()")
    class FindByEmailTests {

        @Test
        @DisplayName("should find user by email")
        void shouldFindUserByEmail() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            User result = userService.findByEmail("test@example.com");

            assertThat(result).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should convert email to lowercase when searching")
        void shouldConvertEmailToLowercaseWhenSearching() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            userService.findByEmail("TEST@EXAMPLE.COM");

            verify(userRepository).findByEmail("test@example.com");
        }
    }

    @Nested
    @DisplayName("toDto()")
    class ToDtoTests {

        @Test
        @DisplayName("should convert user to DTO correctly")
        void shouldConvertUserToDto() {
            UserDto result = userService.toDto(testUser);

            assertThat(result.id()).isEqualTo(testUserId);
            assertThat(result.email()).isEqualTo("test@example.com");
            assertThat(result.displayName()).isEqualTo("Test User");
            assertThat(result.emailVerified()).isFalse();
            assertThat(result.platformOwner()).isFalse();
            assertThat(result.createdAt()).isEqualTo(testUser.getCreatedAt());
        }
    }
}
