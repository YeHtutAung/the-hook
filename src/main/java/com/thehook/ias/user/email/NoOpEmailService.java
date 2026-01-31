package com.thehook.ias.user.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * No-op email service for development/testing.
 * Logs email details instead of actually sending.
 *
 * This is the default implementation when email sending is disabled.
 * To use a real email service, set ias.email.enabled=true and provide
 * an implementation (e.g., SmtpEmailService).
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "ias.email.enabled", havingValue = "false", matchIfMissing = true)
public class NoOpEmailService implements EmailService {

    @Override
    public void sendVerificationEmail(String to, String displayName, String verificationUrl) {
        log.info("""

                ========================================
                EMAIL VERIFICATION (NoOp - Not Sent)
                ----------------------------------------
                To: {}
                Name: {}
                Verification URL: {}
                ========================================
                """, to, displayName, verificationUrl);
    }

    @Override
    public void sendPasswordResetEmail(String to, String displayName, String resetUrl) {
        log.info("""

                ========================================
                PASSWORD RESET (NoOp - Not Sent)
                ----------------------------------------
                To: {}
                Name: {}
                Reset URL: {}
                ========================================
                """, to, displayName, resetUrl);
    }

    @Override
    public void sendInvitationEmail(String to, String organizationName, String inviterName, String inviteUrl) {
        log.info("""

                ========================================
                INVITATION (NoOp - Not Sent)
                ----------------------------------------
                To: {}
                Organization: {}
                Inviter: {}
                Invite URL: {}
                ========================================
                """, to, organizationName, inviterName, inviteUrl);
    }
}
