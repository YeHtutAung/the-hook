package com.thehook.ias.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmailVerificationRepository extends JpaRepository<EmailVerification, UUID> {

    Optional<EmailVerification> findByToken(String token);

    Optional<EmailVerification> findByUserIdAndVerifiedAtIsNull(UUID userId);

    void deleteByUserId(UUID userId);
}
