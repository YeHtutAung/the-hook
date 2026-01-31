package com.thehook.ias.user;

import com.thehook.ias.common.audit.AuditService;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.user.dto.RegisterRequest;
import com.thehook.ias.user.dto.RegisterResponse;
import com.thehook.ias.user.dto.UserDto;
import com.thehook.ias.user.dto.VerifyEmailResponse;
import com.thehook.ias.user.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final EmailService emailService;

    @Value("${ias.base-url:http://localhost:9000}")
    private String baseUrl;

    @Value("${ias.email.verification.expiry-hours:24}")
    private int verificationExpiryHours;

    /**
     * Register a new user with email and password.
     *
     * @param request   registration details
     * @param ipAddress client IP address for audit
     * @return registration response with verification token (MVP)
     */
    @Transactional
    public RegisterResponse registerUser(RegisterRequest request, String ipAddress) {
        String normalizedEmail = request.email().toLowerCase().trim();

        // Check for duplicate email
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw IasException.conflict("Email already registered");
        }

        // Validate password strength
        validatePassword(request.password());

        // Create user with hashed password
        User user = User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(request.password()))
                .displayName(request.displayName().trim())
                .emailVerified(false)
                .enabled(true)
                .platformOwner(false)
                .build();

        user = userRepository.save(user);
        log.info("User registered: {} (ID: {})", user.getEmail(), user.getId());

        // Create email verification token
        EmailVerification verification = createEmailVerification(user);

        // Send verification email (NoOp in MVP, logs to console)
        String verificationUrl = baseUrl + "/auth/verify?token=" + verification.getToken();
        emailService.sendVerificationEmail(user.getEmail(), user.getDisplayName(), verificationUrl);

        // Audit log
        auditService.logUserRegistered(user.getId(), ipAddress);

        // Return response with token (for MVP testing)
        return RegisterResponse.of(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                verification.getToken()
        );
    }

    /**
     * Legacy method for form-based registration.
     */
    @Transactional
    public User register(RegisterRequest request, String ipAddress) {
        RegisterResponse response = registerUser(request, ipAddress);
        return userRepository.findById(response.userId())
                .orElseThrow(() -> IasException.notFound("User", response.userId()));
    }

    /**
     * Create an email verification token for a user.
     */
    @Transactional
    public EmailVerification createEmailVerification(User user) {
        // Invalidate any existing tokens
        emailVerificationRepository.findByUserIdAndVerifiedAtIsNull(user.getId())
                .ifPresent(existing -> {
                    existing.setVerifiedAt(Instant.now()); // Mark as used
                    emailVerificationRepository.save(existing);
                });

        String token = UUID.randomUUID().toString();
        EmailVerification verification = EmailVerification.builder()
                .user(user)
                .token(token)
                .expiresAt(Instant.now().plus(verificationExpiryHours, ChronoUnit.HOURS))
                .build();

        verification = emailVerificationRepository.save(verification);
        log.info("Email verification token created for user: {}", user.getEmail());

        return verification;
    }

    /**
     * Verify user's email using the verification token.
     *
     * @param token verification token
     * @return verification response
     */
    @Transactional
    public VerifyEmailResponse verifyEmailWithResponse(String token) {
        EmailVerification verification = emailVerificationRepository.findByToken(token)
                .orElseThrow(() -> IasException.badRequest("Invalid verification token"));

        if (verification.isExpired()) {
            throw IasException.badRequest("Verification token has expired. Please request a new one.");
        }

        if (verification.isVerified()) {
            throw IasException.badRequest("Email has already been verified");
        }

        // Mark verification as complete
        verification.setVerifiedAt(Instant.now());
        emailVerificationRepository.save(verification);

        // Update user's email verified status
        User user = verification.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {} (ID: {})", user.getEmail(), user.getId());

        return VerifyEmailResponse.success(user.getId(), user.getEmail());
    }

    /**
     * Legacy method for form-based verification.
     */
    @Transactional
    public void verifyEmail(String token) {
        verifyEmailWithResponse(token);
    }

    /**
     * Resend verification email for a user.
     *
     * @param email user's email address
     * @return new verification token (for MVP testing)
     */
    @Transactional
    public String resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> IasException.notFound("User", email));

        if (user.isEmailVerified()) {
            throw IasException.badRequest("Email is already verified");
        }

        EmailVerification verification = createEmailVerification(user);

        String verificationUrl = baseUrl + "/auth/verify?token=" + verification.getToken();
        emailService.sendVerificationEmail(user.getEmail(), user.getDisplayName(), verificationUrl);

        log.info("Verification email resent to: {}", user.getEmail());

        return verification.getToken();
    }

    @Transactional(readOnly = true)
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> IasException.notFound("User", id));
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> IasException.notFound("User", email));
    }

    public UserDto toDto(User user) {
        return new UserDto(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                user.isEmailVerified(),
                user.isPlatformOwner(),
                user.getCreatedAt()
        );
    }

    /**
     * Validate password strength.
     * Can be extended with more complex rules.
     */
    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw IasException.badRequest("Password must be at least 8 characters long");
        }

        if (password.length() > 100) {
            throw IasException.badRequest("Password must not exceed 100 characters");
        }

        // Check for at least one letter and one digit (optional, can be made configurable)
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);

        if (!hasLetter || !hasDigit) {
            throw IasException.badRequest("Password must contain at least one letter and one digit");
        }
    }
}
