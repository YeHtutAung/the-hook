package com.thehook.ias.user.email;

/**
 * Email service interface for sending verification and notification emails.
 * Implementations can use SMTP, SendGrid, AWS SES, etc.
 */
public interface EmailService {

    /**
     * Send email verification link to user.
     *
     * @param to              recipient email address
     * @param displayName     user's display name
     * @param verificationUrl full URL for email verification
     */
    void sendVerificationEmail(String to, String displayName, String verificationUrl);

    /**
     * Send password reset link to user.
     *
     * @param to       recipient email address
     * @param displayName user's display name
     * @param resetUrl full URL for password reset
     */
    void sendPasswordResetEmail(String to, String displayName, String resetUrl);

    /**
     * Send organization invitation email.
     *
     * @param to              recipient email address
     * @param organizationName name of the organization
     * @param inviterName     name of the person who sent the invitation
     * @param inviteUrl       full URL to accept the invitation
     */
    void sendInvitationEmail(String to, String organizationName, String inviterName, String inviteUrl);
}
